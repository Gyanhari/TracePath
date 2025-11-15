#include <pcap.h>
#include <stdio.h>
void packet_handler(u_char *value, const struct pcap_pkthdr *header, const u_char *packet)
{
	// printf("The total payload size is: %d\t\t", header->len - 56);
	// printf("The Packet length is: %d\t\t", header->len);
	int ip_version = packet[14] >> 4;
	if (ip_version == 4)
	{
		printf("The Ip Source for IPv4 is : %d.%d.%d.%d\n", packet[26], packet[27], packet[28], packet[29]);
		printf("The Ip Destination for IPv4 is : %d.%d.%d.%d\n", packet[30], packet[31], packet[32], packet[33]);
	}
	else
	{
		printf("The IP Source for IPv6 is: ");
		for (int i = 0; i < 16; i++)
		{
			if (i % 2 == 0 && i != 0)
			{
				printf(":");
			}
			printf("%02x", packet[22 + i]);
		}
		printf("\n");

		printf("The IP Destination for IPv6 is: ");
		for (int i = 0; i < 16; i++)
		{
			if (i % 2 == 0 && i != 0)
			{
				printf(":");
			}
			printf("%02x", packet[38 + i]);
		}
		printf("\n");
	}
}
int main()
{
	pcap_t *handle;
	const char *dev_name = "wlp2s0";
	char err_buffer[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev_name, 65536, 1, 1000, err_buffer);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open devices %s: %s\n", dev_name, err_buffer);
		return -1;
	}
	pcap_loop(handle, 10, packet_handler, NULL);
	pcap_close(handle);
	return 0;
}



