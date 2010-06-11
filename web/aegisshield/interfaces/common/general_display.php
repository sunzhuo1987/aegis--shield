<?php 
	/*jpgraph库放在了当前目录下
	 *  Note:
	 *  	general_display.php equals to a img file. 
	 * 		So there should be no space between <?php ?>
	 * 		由于<img>标签来使用图片时，该文件中引用的文件应该相对
	 * 		此文件的目录
	 * 
	 * 
	 */

	require_once('../../includes/connection_settings.php');
	require_once('../../classes/adodb/adodb.inc.php');
	require_once('../../classes/alerts_class.php');
	
	
	//Create object
	$DB = NewADOConnection($_type_of_db_server);
	$_res_db = @$DB->Connect($_host, $_user, $_password, $_db_name);
	
	
	$ALERTS = new alerts(&$DB);
	
	$ydata = array();
	$ydata[0] = $ALERTS->TCPPktCnt();
	$ydata[1] = $ALERTS->UDPPktCnt();
	$ydata[2] = $ALERTS->ICMPPktCnt();
	$ydata[3] = $ALERTS->PortscanPktCnt();
	$xlabel = array("TCP", "UDP", "ICMP", "Portscan Traffic");
?>
<?php /*主页的总体图表信息*/

	/*
	 * Lib
	 */
	require_once('jpgraph/src/jpgraph.php');
  	require_once('jpgraph/src/jpgraph_canvas.php');
  	require_once('jpgraph/src/jpgraph_error.php');
  	require_once('jpgraph/src/jpgraph_log.php');
  	require_once('jpgraph/src/jpgraph_pie.php');
  	require_once('jpgraph/src/jpgraph_pie3d.php');
  	require_once('jpgraph/src/jpgraph_scatter.php');
  	require_once('jpgraph/src/jpgraph_radar.php');
  	
  	
	$graph = new PieGraph(250, 250);
  
  	/* Set Margins */
  	$graph->img->SetMargin(50,50,80,80);    
  	$graph->img->SetAntiAliasing();

 
  	$plot[0] = new PiePlot3D($ydata);
  	$plot[0]->SetLegends($xlabel);
 
  	/* Set Title */
  	$graph->title->Set("Traffic Profile by Protocol");
  	$graph->Add($plot[0]);
  	$graph->Stroke(); 
?>