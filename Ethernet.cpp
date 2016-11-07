/* Zornitsa Chopova */
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void PacketHandler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);
void PacketInfo(const u_char* packet);
void WriteAddress(u_char* ptr, FILE* file);


int main(int argc, char *argv[])
{
	char errorBuffer[PCAP_ERRBUF_SIZE]; /* 256 */

	pcap_t* handler = pcap_open_offline("src/hw2.pcap", errorBuffer);

    if(!handler) {
        printf("pcap_open_offline(): %s\n", errorBuffer);
        return 1;
    }

    pcap_loop(handler, 0, PacketHandler, NULL);
    pcap_close(handler);

    return 0;
}

void PacketHandler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
    PacketInfo(packet);
}

void PacketInfo(const u_char* packet)
{
	struct ether_header* ptrEthernet = (struct ether_header*) packet;

	FILE* file = fopen("output.txt", "a"); /* Append */
	if (!file) {
	    printf("Error opening file!\n");
	    return;
	}

	/* Destination address */
	u_char* ptr = ptrEthernet->ether_dhost;
	WriteAddress(ptr, file);

	/* Source address */
	ptr = ptrEthernet->ether_shost;
	WriteAddress(ptr, file);

	/* Ethernet type */
	fprintf(file, "%#06x\n", ntohs(ptrEthernet->ether_type));
	fclose(file);
}

void WriteAddress(u_char* ptr, FILE* file)
{
	int i = ETHER_ADDR_LEN; /* length is 6 */
	for(; i > 0; i--) {
		if(i == ETHER_ADDR_LEN) {
			fprintf(file, "%02x", *ptr);
		} else {
			fprintf(file, ":%02x", *ptr);
		}
		ptr++;
	}
	fprintf(file, " ");
}
