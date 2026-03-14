let @pool = getopt("pool", "64:ff9b:dead:beef::/96")

tracepoint:fib6:fib6_table_lookup 
/ args->err != 0 /
{
  printf("tb_id: %d, err: %d, src: %s, dst: %s\n", args->tb_id, args->err, ntop(args->src), ntop(args->dst)); 
}


tracepoint:fib:fib_table_lookup 
/ args->err != 0 /
{
  printf("tb_id: %d, err: %d, src: %s, dst: %s\n", args->tb_id, args->err, ntop(args->src), ntop(args->dst)); 
}
