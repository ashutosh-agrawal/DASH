#ifndef _SIRIUS_OUTBOUND_P4_
#define _SIRIUS_OUTBOUND_P4_

#include "dash_headers.p4"
#include "dash_acl.p4"
#include "dash_conntrack.p4"
#include "dash_service_tunnel.p4"

control outbound(inout headers_t hdr,
                 inout metadata_t meta)
{
    action route_vnet(bit<16> dst_vnet_id,
                      bit<1> metering_policy_en,
                      bit<16> metering_class) {
        meta.dst_vnet_id = dst_vnet_id;
	meta.metering_policy_en = metering_policy_en;
	meta.metering_class = metering_class;
    }

    action route_vnet_direct(bit<16> dst_vnet_id,
                             bit<1> metering_policy_en,
                             bit<16> metering_class,
                             bit<1> is_overlay_ip_v4_or_v6,
                             IPv4ORv6Address overlay_ip) {
        meta.dst_vnet_id = dst_vnet_id;
        meta.lkup_dst_ip_addr = overlay_ip;
        meta.is_lkup_dst_ip_v6 = is_overlay_ip_v4_or_v6;
	meta.metering_policy_en = metering_policy_en;
	meta.metering_class = metering_class;
    }

    action route_direct(bit<1> metering_policy_en,
                        bit<16> metering_class) {
        /* send to underlay router without any encap */
	meta.metering_policy_en = metering_policy_en;
	meta.metering_class = metering_class;
    }

    action drop() {
        meta.dropped = true;
    }

    action route_service_tunnel(bit<1> is_overlay_dip_v4_or_v6,
                                IPv4ORv6Address overlay_dip,
                                bit<1> is_overlay_dip_mask_v4_or_v6,
                                IPv4ORv6Address overlay_dip_mask,
                                bit<1> is_overlay_sip_v4_or_v6,
                                IPv4ORv6Address overlay_sip,
                                bit<1> is_overlay_sip_mask_v4_or_v6,
                                IPv4ORv6Address overlay_sip_mask,
                                bit<1> is_underlay_dip_v4_or_v6,
                                IPv4ORv6Address underlay_dip,
                                bit<1> is_underlay_sip_v4_or_v6,
                                IPv4ORv6Address underlay_sip,
                                dash_encapsulation_t dash_encapsulation,
                                bit<1> metering_policy_en,
                                bit<16> metering_class,
                                bit<24> tunnel_key) {
        /* Assume the overlay addresses provided are always IPv6 and the original are IPv4 */
        /* assert(is_overlay_dip_v4_or_v6 == 1 && is_overlay_sip_v4_or_v6 == 1);
        assert(is_overlay_dip_mask_v4_or_v6 == 1 && is_overlay_sip_mask_v4_or_v6 == 1);
        assert(is_underlay_dip_v4_or_v6 != 1 && is_underlay_sip_v4_or_v6 != 1); */
        meta.encap_data.original_overlay_dip = hdr.ipv4.src_addr;
        meta.encap_data.original_overlay_sip = hdr.ipv4.dst_addr;

        service_tunnel_encode(hdr,
                              overlay_dip,
                              overlay_dip_mask,
                              overlay_sip,
                              overlay_sip_mask);

        /* encapsulation will be done in apply block based on dash_encapsulation */
        meta.encap_data.underlay_dip = underlay_dip == 0 ? meta.encap_data.original_overlay_dip : (IPv4Address)underlay_dip;
        meta.encap_data.underlay_sip = underlay_sip == 0 ? meta.encap_data.original_overlay_sip : (IPv4Address)underlay_sip;
        meta.encap_data.overlay_dmac = hdr.ethernet.dst_addr;
        meta.encap_data.dash_encapsulation = dash_encapsulation;
        meta.encap_data.service_tunnel_key = tunnel_key;

	meta.metering_policy_en = metering_policy_en;
	meta.metering_class = metering_class;
    }

#ifdef TARGET_BMV2_V1MODEL

    direct_counter(CounterType.packets_and_bytes) routing_counter;
#endif // TARGET_BMV2_V1MODEL
#ifdef TARGET_DPDK_PNA
#ifdef DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
    // See the #ifdef with same preprocessor symbol in dash_pipeline.p4
    DirectCounter<bit<64>>(PNA_CounterType_t.PACKETS_AND_BYTES) routing_counter;
#endif  // DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
#endif  // TARGET_DPDK_PNA

    @name("outbound_routing|dash_outbound_routing")
    table routing {
        key = {
            meta.eni_id : exact @name("meta.eni_id:eni_id");
            meta.is_overlay_ip_v6 : exact @name("meta.is_overlay_ip_v6:is_destination_v4_or_v6");
            meta.dst_ip_addr : lpm @name("meta.dst_ip_addr:destination");
        }

        actions = {
            route_vnet; /* for expressroute - ecmp of overlay */
            route_vnet_direct;
            route_direct;
            route_service_tunnel;
            drop;
        }
        const default_action = drop;

#ifdef TARGET_BMV2_V1MODEL
        counters = routing_counter;
#endif // TARGET_BMV2_V1MODEL
#ifdef TARGET_DPDK_PNA
#ifdef DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
        pna_direct_counter = routing_counter;
#endif // DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
#endif // TARGET_DPDK_PNA
    }

    action set_tunnel_mapping(IPv4Address underlay_dip,
                              EthernetAddress overlay_dmac,
                              bit<1> override_meter,
                              bit<16> metering_class,
	                      bit<1> use_dst_vnet_vni) {
        if (use_dst_vnet_vni == 1)
            meta.vnet_id = meta.dst_vnet_id;
        meta.encap_data.overlay_dmac = overlay_dmac;
        meta.encap_data.underlay_dip = underlay_dip;
	meta.override_meter = override_meter;
	meta.mapping_metering_class = metering_class;
    }

#ifdef TARGET_BMV2_V1MODEL
    direct_counter(CounterType.packets_and_bytes) ca_to_pa_counter;
#endif // TARGET_BMV2_V1MODEL
#ifdef TARGET_DPDK_PNA
#ifdef DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
    DirectCounter<bit<64>>(PNA_CounterType_t.PACKETS_AND_BYTES) ca_to_pa_counter;
#endif  // DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
#endif  // TARGET_DPDK_PNA

    @name("outbound_ca_to_pa|dash_outbound_ca_to_pa")
    table ca_to_pa {
        key = {
            /* Flow for express route */
            meta.dst_vnet_id: exact @name("meta.dst_vnet_id:dst_vnet_id");
            meta.is_lkup_dst_ip_v6 : exact @name("meta.is_lkup_dst_ip_v6:is_dip_v4_or_v6");
            meta.lkup_dst_ip_addr : exact @name("meta.lkup_dst_ip_addr:dip");
        }

        actions = {
            set_tunnel_mapping;
            @defaultonly drop;
        }
        const default_action = drop;

#ifdef TARGET_BMV2_V1MODEL
        counters = ca_to_pa_counter;
#endif // TARGET_BMV2_V1MODEL
#ifdef TARGET_DPDK_PNA
#ifdef DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
        pna_direct_counter = ca_to_pa_counter;
#endif // DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
#endif // TARGET_DPDK_PNA
    }

    action set_vnet_attrs(bit<24> vni) {
        meta.encap_data.vni = vni;
    }

    @name("vnet|dash_vnet")
    table vnet {
        key = {
            meta.vnet_id : exact @name("meta.vnet_id:vnet_id");
        }

        actions = {
            set_vnet_attrs;
        }
    }

    action set_metering_class(bit<16> metering_class) {
	meta.metering_class = metering_class;
    }

    @name("meter_policy|dash_meter_policy")
    table meter_policy {
	key = {
	    meta.meter_policy : ternary @name("meta.meter_policy:meter_policy");
            meta.is_lkup_dst_ip_v6 : exact @name("meta.is_lkup_dst_ip_v6:is_dip_v4_or_v6");
            meta.lkup_dst_ip_addr : exact @name("meta.lkup_dst_ip_addr:dip");
	}
	actions = {
	    set_metering_class;
	}
    }

    apply {
#ifdef STATEFUL_P4
           ConntrackOut.apply(0);
#endif /* STATEFUL_P4 */

#ifdef PNA_CONNTRACK
        ConntrackOut.apply(hdr, meta);
#endif // PNA_CONNTRACK

        /* ACL */
        if (!meta.conntrack_data.allow_out) {
            acl.apply(hdr, meta);
        }

#ifdef STATEFUL_P4
            ConntrackIn.apply(1);
#endif /* STATEFUL_P4 */

#ifdef PNA_CONNTRACK
        ConntrackIn.apply(hdr, meta);
#endif // PNA_CONNTRACK

        meta.lkup_dst_ip_addr = meta.dst_ip_addr;
        meta.is_lkup_dst_ip_v6 = meta.is_overlay_ip_v6;

        switch (routing.apply().action_run) {
            route_vnet_direct:
            route_vnet: {
                ca_to_pa.apply();
                vnet.apply();

                vxlan_encap(hdr,
                            meta.encap_data.underlay_dmac,
                            meta.encap_data.underlay_smac,
                            meta.encap_data.underlay_dip,
                            meta.encap_data.underlay_sip,
                            meta.encap_data.overlay_dmac,
                            meta.encap_data.vni);
             }
           route_service_tunnel: {
                if (meta.encap_data.dash_encapsulation == dash_encapsulation_t.VXLAN) {
                    vxlan_encap(hdr,
                                meta.encap_data.underlay_dmac,
                                meta.encap_data.underlay_smac,
                                meta.encap_data.underlay_dip,
                                meta.encap_data.underlay_sip,
                                meta.encap_data.overlay_dmac,
                                meta.encap_data.service_tunnel_key);
                } else if (meta.encap_data.dash_encapsulation == dash_encapsulation_t.NVGRE) {
                    nvgre_encap(hdr,
                                meta.encap_data.underlay_dmac,
                                meta.encap_data.underlay_smac,
                                meta.encap_data.underlay_dip,
                                meta.encap_data.underlay_sip,
                                meta.encap_data.overlay_dmac,
                                meta.encap_data.service_tunnel_key);
                } else {
                    drop();
                }
             }
         }

	if (meta.metering_policy_en == 1)
	    meter_policy.apply();

	if (meta.override_meter == 1)
	    meta.metering_class = meta.mapping_metering_class;
    }
}

#endif /* _SIRIUS_OUTBOUND_P4_ */
