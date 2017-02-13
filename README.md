crslmnl
=======

Rust wrapper of libmnl, with less tesging.


sample
------

see examples


requires
--------

  * libmnl


links
-----

* libmnl: http://netfilter.org/projects/libmnl/


stackoverflow
-------------

thanks to [Shepmaster](http://stackoverflow.com/users/155423/shepmaster)

* [Cannot use downcast Any to an array containing references](http://stackoverflow.com/questions/40922855/cannot-use-downcast-any-to-an-array-containing-references)
* [Is there a proper way to create a const from an enum value in a crate?](http://stackoverflow.com/questions/41501411/is-there-a-proper-way-to-create-a-const-from-an-enum-value-in-a-crate)


comparison
----------

| original				| cgolmnl			| remarks			|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_attr_get_type			| Nlattr.atype			|				|
| mnl_attr_get_len			| Nlattr.len			|				|
| mnl_attr_get_payload_len		| Nlattr.payload_len		|				|
| mnl_attr_get_payload			| Nlattr.payload		|				|
| mnl_attr_get_payload			| Nlattr.payload_mut		|				|
| mnl_attr_ok				| Nlattr.ok			|				|
| mnl_attr_next				| Nlattr.next			| 				|
| mnl_attr_type_valid			| Nlattr.type_valid		| 				|
| mnl_attr_validate			| Nlattr.validate		| 				|
| mnl_attr_validate2			| Nlattr.validate2		| 				|
| mnl_attr_parse			| Nlattr.parse			| 				|
| mnl_attr_parse_nested			| Nlattr.parse_nested		| 				|
| mnl_attr_parse_payload		| parse_payload			| 				|
| mnl_attr_get_u8			| Nlattr.u8			|				|
| mnl_attr_get_u16			| Nlattr.u16			|				|
| mnl_attr_get_u32			| Nlattr.u32			|				|
| mnl_attr_get_u64			| Nlattr.u64			|				|
| mnl_attr_get_str			| Nlattr.string			|				|
| 					| Nlattr.str			|				|
| mnl_attr_put				| Nlmsg.put			|				|
| mnl_attr_put_u8			| Nlmsg.PutU8			|				|
| mnl_attr_put_u16			| Nlmsg.put_u16			|				|
| mnl_attr_put_u32			| Nlmsg.put_u32			|				|
| mnl_attr_put_u64			| Nlmsg.put_u64			|				|
| mnl_attr_put_str			| Nlmsg.put_str			|				|
| mnl_attr_put_strz			| Nlmsg.put_strz		|				|
| mnl_attr_put_check			| Nlmsg.put_check		|				|
| mnl_attr_put_u8_check			| Nlmsg.put_u8_check		|				|
| mnl_attr_put_u16_check		| Nlmsg.put_u16_check		|				|
| mnl_attr_put_u32_check		| Nlmsg.put_u32_check		|				|
| mnl_attr_put_u64_check		| Nlmsg.put_u64_check		|				|
| mnl_attr_put_str_check		| Nlmsg.put_str_check		|				|
| mnl_attr_put_strz_check		| Nlmsg.put_strz_check		|				|
| mnl_attr_nest_start			| Nlmsg.nest_start		|				|
| mnl_attr_nest_start_check		| Nlmsg.nest_start_check	|				|
| mnl_attr_nest_end			| Nlmsg.nest_end		|				|
| mnl_attr_nest_cancel			| Nlmsg.nest_cancel		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_nlmsg_size			| Nlmsg.size			|				|
| mnl_nlmsg_get_payload_len		| Nlmsg.payload_len		|				|
| mnl_nlmsg_put_header			| Nlmsg::new			|				|
| mnl_nlmsg_put_header			| Nlmsg.put_header		|				|
| mnl_nlmsg_put_extra_header		| Nlmsg.put_extra_header	|  				|
| mnl_nlmsg_get_paylod			| Nlmsg.payload			| 				|
| mnl_nlmsg_get_paylod			| Nlmsg.payload_mut		| 				|
| mnl_nlmsg_get_payload_offset		| Nlmsg.payload_offset		| 				|
| mnl_nlmsg_get_payload_offset		| Nlmsg.payload_offset_mut	| 				|
| mnl_nlmsg_ok				| Nlmsg.ok			| 				|
| mnl_nlmsg_next			| Nlmsg.next			|				|
| mnl_nlmsg_get_payload_tail		| Nlmsg.payload_tail		| 				|
| mnl_nlmsg_get_payload_tail		| Nlmsg.payload_tail_mut	| 				|
| mnl_nlmsg_seq_ok			| Nlmsg.seq_ok			|				|
| mnl_nlmsg_portid_ok			| Nlmsg.portid_ok		| 				|
| mnl_nlmsg_fprintf			| Nlmsg.fprint			|				|
| mnl_nlmsg_batch_start			| NlmsgBatch::start		|				|
| mnl_nlmsg_batch_stop			| NlmsgBatch.drop		| 				|
| mnl_nlmsg_batch_next			| NlmsgBatch.next		|	 			|
| mnl_nlmsg_batch_reset			| NlmsgBatch.reset		|	 			|
| mnl_nlmsg_batch_size			| NlmsgBatch.size		|	 			|
| mnl_nlmsg_batch_head			| NlmsgBatch.head		|	 			|
| mnl_nlmsg_batch_current		| NlmsgBatch.current		|				|
| mnl_nlmsg_batch_is_empty		| NlmsgBatch.is_empty		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_cb_run				| cb_run			| 				|
| mnl_cb_run2				| cb_run2			| changed signature		|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_socket_get_fd			| Socket.as_raw_fd		|				|
| mnl_socket_get_portid			| Socket.portid			|				|
| mnl_socket_open			| Socket::open			| 				|
| mnl_socket_open2			| Socket::open2			| 				|
| mnl_socket_fdopen			| Socket::fdopen		| 				|
| mnl_socket_bind			| Socket.bind			|				|
| mnl_socket_sendto			| Socket.sendto			|				|
| (add)					| Socket.send_nlmsg		|				|
| (add)					| Socket.send_batch		|				|
| mnl_socket_recvfrom			| Socket.recvfrom		|				|
| mnl_socket_close			| Socket.close			|				|
| mnl_socket_setsockopt			| Socket.setsockopt		|				|
| mnl_socket_getsockopt			| Socket.getsockopt		|				|
| ------------------------------------- | ----------------------------- | ----------------------------- |
| mnl_attr_for_each			| Nlmsg.attrs			|				|
| mnl_attr_for_each_nested		| Nlattr.nesteds		|				|
