 #include <pcap.h>
 #include <stdio.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <map>
#include <unordered_map>
#include <iostream>
#include <string>
#include <string_view>
#include <sstream>
#include <vector>

struct Session {
    std::map<uint32_t, std::string> cache;
};

std::unordered_map<uint16_t, Session> manager;

std::string assemble(const std::map<uint32_t, std::string> & cache) {
    std::vector<std::string_view> t;
    t.reserve(cache.size());

    auto iter = cache.begin();
    if (iter == cache.end()) {
        return "";
    }

    t.emplace_back(iter->second);
    auto next_seq = iter->first + iter->second.size();
    size_t total = iter->second.size();
    ++iter;

    while (iter != cache.end()) {
        if (iter->first > next_seq) {
            throw std::runtime_error("incomplete data in cache");
        }
        auto skip = next_seq - iter->first;
        t.emplace_back(iter->second.data() + skip , iter->second.size() - skip);
        next_seq = iter->first + iter->second.size();
        total += iter->second.size() - skip;
        ++iter;
    }

    std::string r;
    r.reserve(total);
    for (const auto & seg : t) {
        r.append(seg);
    }
    return r;
}

void report(uint16_t port, const std::string & s) {
    std::cout << std::string(100, '-') << '\n';
    std::cout << "port : " << port << '\n';
    std::cout << s << std::endl;
}

bool process(const char *packet, size_t size) {
    auto eth = (struct ethhdr *)packet;

    if (ntohs(eth->h_proto) != ETH_P_IP) {
		throw std::runtime_error(std::string("wrong lay 3 proto"));
    }

    auto ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    auto total_length = ntohs(ip->tot_len);
    if (total_length + sizeof(struct ethhdr) > size) {
		throw std::runtime_error("inconsistent ip length");
    }
    if (total_length + sizeof(struct ethhdr) != size) {
        std::cerr << "warning: captured size greater than expected" << std::endl;
    }

    auto tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
    char *payload = (char *)tcp + tcp->doff * 4;
    if ((char *)ip + total_length < payload) {
		throw std::runtime_error("inconsistent tcp offset ");
    }
    size_t len = (char *)ip + total_length - payload;

    auto dst_port = ntohs(tcp->dest);
    auto src_port = ntohs(tcp->source);
    if (dst_port != 8888 && src_port != 8888) {
		throw std::runtime_error("inconsistent tcp port");
    }

    auto session_iter = manager.end();

    if (src_port == 8888) {
        session_iter = manager.find(dst_port);

        if (tcp->syn && tcp->ack) {
            manager.emplace(dst_port, Session{});
        } else if (tcp->rst && session_iter != manager.end()) {
            report(dst_port, assemble(session_iter->second.cache));
            manager.erase(session_iter);
        }
    } else if (dst_port == 8888) {
        session_iter = manager.find(src_port);

        if (session_iter != manager.end() && tcp->fin) {
            report(src_port, assemble(session_iter->second.cache));
            manager.erase(session_iter);
        } else if (session_iter != manager.end() && len > 0) {
            auto seq = ntohl(tcp->seq);
            auto cache_iter = session_iter->second.cache.find(seq);
            if (cache_iter == session_iter->second.cache.end()) {
                session_iter->second.cache.emplace(seq, std::string(payload, len));
            } else if (cache_iter->second.size() < len) {
                cache_iter->second = std::string(payload, len);
            }
        }
    }

    return false;
}

int main(int argc, char *argv[]) {
	pcap_t *handle;			/* Session handle */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "tcp port 8888";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

    const char *dev = (argc >= 2) ? argv[1] : "lo";

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device lo: %s\n", errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
    bool done = false;
    while (!done) {
        packet = pcap_next(handle, &header);
        done = process((const char *)packet, header.len);
    }

	/* And close the session */
	pcap_close(handle);
	return(0);
 }
