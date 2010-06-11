<?php
// Alerts Class

class alerts{
	
	var $DB;

	//构造函数
	function alerts($DB){
		$this->DB=$DB;
	}


	function sensorCnt(){
		$myRow = $this->DB->GetRow("SELECT COUNT(DISTINCT event.sid) FROM event");
		
		$tot = $myRow[0];
		
		return $tot;
	}
	
	function eventCnt(){
		$myRow = $this->DB->GetRow("SELECT COUNT(*) FROM event");

		$tot = $myRow[0];

		return $tot;
	}
	
	function eventBySensor($sensorID){
		$myRow = $this->DB->GetRow("SELECT COUNT(*) FROM event WHERE sid = '".$sensorID."'");

		$tot = $myRow[0];
		
		return $tot;
	}
	
	function uniqueAlertCnt(){
		$myRow = $this->DB->GetRow("SELECT COUNT(DISTINCT signature) FROM event");
	
		$tot = $myRow[0];
		
		return $tot;
	}
	
	//Unique Alert by Sensor
	function uniqueAlertCntBySensor($sensorID){
  		$myRow = $this->DB->GetRow("SELECT COUNT(DISTINCT signature) FROM event WHERE sid = '".$sensorID."'");
		
		$tot = $myRow[0];

		return $tot;

	}
	function uniqueIpSrcCnt(){
		$myRow = $this->DB->GetRow("SELECT COUNT(DISTINCT iphdr.ip_src) FROM iphdr");
		
		$tot = $myRow[0];
		
		return $tot;
	}
	
	function uniqueIpDstCnt(){
		$myRow = $this->DB->GetRow("SELECT COUNT(DISTINCT iphdr.ip_dst) FROM iphdr");
	
		$tot = $myRow[0];
		
		return $tot;
	}
	
	function uniqueLinkCnt(){
		$myRow = $this->DB->GetRow("SELECT COUNT(DISTINCT iphdr.ip_src, iphdr.ip_dst, iphdr.ip_proto) FROM iphdr");
	
		$tot = $myRow[0];
		
		return $tot;
	}

	function uniqueSrcPortCnt(){
		$tcpSrcP = $this->uniqueTcpSrcPortCnt();
		$udpSrcP = $this->uniqueUdpSrcPortCnt();
		$tot = (int)$tcpSrcP + (int)$udpSrcP;
		return $tot;
	}
	
	function uniqueDstPortCnt(){
		$tcpDstP = $this->uniqueTcpDstPortCnt();
		$udpDstP = $this->uniqueUdpDstPortCnt();
		$tot = (int)$tcpDstP + (int)$udpDstP;
		
		return $tot;
	}
	
	function uniqueTcpSrcPortCnt(){
		$myRow = $this->DB->GetRow("SELECT COUNT(DISTINCT tcphdr.tcp_sport) FROM tcphdr");
	
		$tot = $myRow[0];
		return $tot;
	}
	
	function uniqueUdpSrcPortCnt(){
		$myRow = $this->DB->GetRow("SELECT COUNT(DISTINCT udphdr.udp_sport) FROM udphdr");
		
		$tot = $myRow[0];
		return $tot;
	}
	
	function uniqueTcpDstPortCnt(){
		$myRow = $this->DB->GetRow("SELECT COUNT(DISTINCT tcphdr.tcp_dport) FROM tcphdr");
	
		$tot = $myRow[0];
		return $tot;
	}
	
	function uniqueUdpDstPortCnt(){
		$myRow = $this->DB->GetRow("SELECT COUNT(DISTINCT udphdr.udp_dport) FROM udphdr");
		
		$tot = $myRow[0];
		return $tot;
	}
	
	/*
	 * 
	 */
	
	function TCPPktCnt()
	{
   		$myRow = $this->DB->GetRow("SELECT count(*) FROM iphdr WHERE ip_proto=6");
   		
   		$tot = $myRow[0];
		return $tot;
	}

	function UDPPktCnt()
	{
   		$myRow = $this->DB->GetRow("SELECT count(*) FROM iphdr WHERE ip_proto=17");
   		
   		$tot = $myRow[0];
		return $tot;
	}

	function ICMPPktCnt()
	{
   		$myRow = $this->DB->GetRow("SELECT count(*) FROM iphdr WHERE ip_proto=1");
   		
   		$tot = $myRow[0];
		return $tot;
	}

	function PortscanPktCnt()
	{
   		$myRow = $this->DB->GetRow("SELECT count(event.sid) FROM event ".
                                 "LEFT JOIN signature ON event.signature=signature.sig_id ".
                                 "WHERE sig_name LIKE 'spp_portscan%'");
   		
   		$tot = $myRow[0];
		return $tot;
	}
	
}

?>