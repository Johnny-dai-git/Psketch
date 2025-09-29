/*
 * eBPF Helper Functions
 * Contains utility functions for flow processing
 */

static __always_inline bool same_flow( struct flow_stats_sketch *stats_sketch, struct flow_key key ){
    if( stats_sketch->src_ip == key.src_ip && stats_sketch->dst_ip == key.dst_ip && stats_sketch->src_port == key.src_port
		   && stats_sketch->dst_port == key.dst_port && stats_sketch->protocol == key.protocol){
      return true;
    }else{
      return false;
    }
}

static __always_inline void assign_tuples( struct flow_stats_sketch *stats_sketch, struct flow_key key ){

    // Tempory 5-tuples
    u32 temp_src_ip;
    u32 temp_dst_ip;
    u16 temp_src_port;
    u16 temp_dst_port;
    u8 temp_protocol;
    // Keep the original 5-tuples
    temp_src_ip = stats_sketch->src_ip;
    temp_dst_ip = stats_sketch->dst_ip;
    temp_src_port = stats_sketch->src_port;
    temp_dst_port = stats_sketch->dst_port;
    temp_protocol = stats_sketch->protocol;
    // Transfer the 5-tuple information
    stats_sketch->src_ip = key.src_ip;
    stats_sketch->dst_ip = key.dst_ip;
    stats_sketch->src_port = key.src_port;
	stats_sketch->dst_port = key.dst_port;
    stats_sketch->protocol = key.protocol;
    // Transfer the 5-tuple information
    key.src_ip = temp_src_ip;
    key.dst_ip = temp_dst_ip;
    key.src_port = temp_src_port;
    key.dst_port = temp_dst_port;
    key.protocol = temp_protocol;
    return;
}
