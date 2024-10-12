#!/usr/sbin/dtrace -s

/*******************************************************************************
  Platform     : FreeBSD bsd 14.1-RC1
  Option       : -qs
  Description  : Check Timer Activation
  Comment      :
*******************************************************************************/

BEGIN
{
    /*
    Convert target IP address to real memory value.
    Can calcurate by below command. (ex: 172.20.10.84 is 0x540a14ac)
    echo 172.20.10.84 | awk -F"." '{printf "0x%02x%02x%02x%02x\n", $4, $3, $2, $1}'
    */
    target = 0xca5214ac;
    printf("target ip: %d.%d.%d.%d (0x%x)\n", target & 0xff, (target >> 8) & 0xff, (target >> 16) & 0xff, (target >> 24) & 0xff, target);
    tmp_tcp = (struct tcpcb *)0;
}

fbt::tcp_timer_activate:entry
{
    this->msec = (walltimestamp % 1000000000) / 1000000;
    this->tcp = (struct tcpcb *)arg0;
    this->srcip = this->tcp->t_inpcb.inp_inc.inc_ie.ie_dependladdr.id46_addr.ia46_addr4.s_addr;
    this->srcport = this->tcp->t_inpcb.inp_inc.inc_ie.ie_lport;
    this->dstip = this->tcp->t_inpcb.inp_inc.inc_ie.ie_dependfaddr.id46_addr.ia46_addr4.s_addr;
    this->dstport = this->tcp->t_inpcb.inp_inc.inc_ie.ie_fport;
    if (target == this->dstip) {
        printf("%Y.%03dZ %s:%s pid: %5d", walltimestamp, this->msec, probefunc, probename, pid);
        printf(" tcpcb: 0x%p which: %d delta: %6d", arg0, arg1, arg2);
        printf(" t_rxtshift: %2d t_rxtcur: %5d t_srtt: %5d t_rttvar: %5d", this->tcp->t_rxtshift, this->tcp->t_rxtcur, this->tcp->t_srtt, this->tcp->t_rttvar);
        printf(" src: %d.%d.%d.%d:%d", this->srcip & 0xff, (this->srcip >> 8) & 0xff, (this->srcip >> 16) & 0xff,(this->srcip >> 24) & 0xff, (this->srcport << 8| this->srcport >> 8));
        printf(" dst: %d.%d.%d.%d:%d", this->dstip & 0xff, (this->dstip >> 8) & 0xff, (this->dstip >> 16) & 0xff,(this->dstip >> 24) & 0xff, (this->dstport << 8| this->dstport >> 8));
        printf("\n");
    }
}

fbt::tcp_xmit_timer:entry
{
    this->msec = (walltimestamp % 1000000000) / 1000000;
    this->tcp = (struct tcpcb *)arg0;
    this->srcip = this->tcp->t_inpcb.inp_inc.inc_ie.ie_dependladdr.id46_addr.ia46_addr4.s_addr;
    this->srcport = this->tcp->t_inpcb.inp_inc.inc_ie.ie_lport;
    this->dstip = this->tcp->t_inpcb.inp_inc.inc_ie.ie_dependfaddr.id46_addr.ia46_addr4.s_addr;
    this->dstport = this->tcp->t_inpcb.inp_inc.inc_ie.ie_fport;
    if (target == this->dstip) {
        tmp_tcp = this->tcp;
        printf("%Y.%03dZ %s:%s pid: %5d", walltimestamp, this->msec, probefunc, probename, pid);
        printf(" tcpcb: 0x%p delta: %6d", arg0, arg1);
        printf(" t_rxtshift: %2d t_rxtcur: %5d t_srtt: %5d t_rttvar: %5d", this->tcp->t_rxtshift, this->tcp->t_rxtcur, this->tcp->t_srtt, this->tcp->t_rttvar);
        printf(" src: %d.%d.%d.%d:%d", this->srcip & 0xff, (this->srcip >> 8) & 0xff, (this->srcip >> 16) & 0xff,(this->srcip >> 24) & 0xff, (this->srcport << 8| this->srcport >> 8));
        printf(" dst: %d.%d.%d.%d:%d", this->dstip & 0xff, (this->dstip >> 8) & 0xff, (this->dstip >> 16) & 0xff,(this->dstip >> 24) & 0xff, (this->dstport << 8| this->dstport >> 8));
        printf("\n");
    }
}

fbt::tcp_xmit_timer:return
{
    if (tmp_tcp) {
        this->msec = (walltimestamp % 1000000000) / 1000000;
        this->tcp = (struct tcpcb *)tmp_tcp;
        this->srcip = this->tcp->t_inpcb.inp_inc.inc_ie.ie_dependladdr.id46_addr.ia46_addr4.s_addr;
        this->srcport = this->tcp->t_inpcb.inp_inc.inc_ie.ie_lport;
        this->dstip = this->tcp->t_inpcb.inp_inc.inc_ie.ie_dependfaddr.id46_addr.ia46_addr4.s_addr;
        this->dstport = this->tcp->t_inpcb.inp_inc.inc_ie.ie_fport;
        printf("%Y.%03dZ %s:%s pid: %5d", walltimestamp, this->msec, probefunc, probename, pid);
        printf(" tcpcb: 0x%p", this->tcp);
        printf(" t_rxtshift: %2d t_rxtcur: %5d t_srtt: %5d t_rttvar: %5d", this->tcp->t_rxtshift, this->tcp->t_rxtcur, this->tcp->t_srtt, this->tcp->t_rttvar);
        printf(" src: %d.%d.%d.%d:%d", this->srcip & 0xff, (this->srcip >> 8) & 0xff, (this->srcip >> 16) & 0xff,(this->srcip >> 24) & 0xff, (this->srcport << 8| this->srcport >> 8));
        printf(" dst: %d.%d.%d.%d:%d", this->dstip & 0xff, (this->dstip >> 8) & 0xff, (this->dstip >> 16) & 0xff,(this->dstip >> 24) & 0xff, (this->dstport << 8| this->dstport >> 8));
        printf("\n");
        tmp_tcp = 0;
    }
}
