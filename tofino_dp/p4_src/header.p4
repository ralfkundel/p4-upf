header queue_id_t {
	bit<32> queue_id;
}

header ethernet_t {
	bit<48> dstAddr;
	bit<48> srcAddr;
	bit<16> etherType;
}


header ipv4_t {
	bit<4>  version;
	bit<4>  ihl;
	bit<8>  diffServ;
	bit<16> paketlen;
	bit<16> id;
	bit<3>  flags;
	bit<13> fragOffset;
	bit<8>  ttl;
	bit<8>  protocol;
	bit<16> header_checksum;
	bit<32> srcAddr;
	bit<32> dstAddr;
}

header udp_t {
	bit<16> srcPort;
	bit<16> dstPort;
	bit<16> len;
	bit<16> checksum;
}

header gtp_v1_t {
    bit<3> version;
    bit<1> protocolType;
    bit<1> reserved;
    //bit<1> extensionHeaderFlag; // E bit
    //bit<1> seqNoFlag;           // S bit
    //bit<1> npduNoFlag;          // PN bit
    bit<1> ex_flag;    /* next extension hdr present? */
    bit<1> seq_flag;   /* sequence no. */
    bit<1> npdu_flag;  /* n-pdn number present ? */
    bit<8> messageType;
    bit<16> messageLength;
    bit<32> teid;               //Tunnel endpoint identifier
}

header gtp_v1_seq_t{
    bit<16> seq;
    bit<8> npdu;
    bit<8> next_extension_hdr_type;
}

header gtp_v1_ext_pdu_t{
    bit<8> extension_length;
    bit<16> foo;
    bit<8> next_extension_hdr_type; //0
}

// STRUCTS
struct headers_t {
    queue_id_t queue_id;
	ethernet_t ethernet;
	ipv4_t ipv4;
	udp_t udp;
    gtp_v1_t gtp_v1;
    gtp_v1_seq_t gtp_v1_seq;
    gtp_v1_ext_pdu_t gtp_v1_ext_pdu;
    ipv4_t ipv4_inner;
	ethernet_t ethernet_inner;
    ipv4_t ipv4_outer;

}


struct metadata_t {
    bit<32> dst_ip;
    bit<3> usds;
    bit<2> us_load_balance;
    bit<1> is_processed;
    bit<1> is_encap;
}
