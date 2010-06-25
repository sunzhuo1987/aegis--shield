<?php 

	require_once('../../includes/connection_settings.php');
	require_once('../../classes/adodb/adodb.inc.php');
	require_once('../../classes/approto_class.php');
	/*
	 * 
	 */
	//Create object
	$DB = NewADOConnection($_type_of_db_server);
	$_res_db = @$DB->Connect($_host, $_user, $_password, $_db_name);
	
	
	$APPROTO = new approto(&$DB);
	
	$APPROTO->getProtoDataSet($xdata);
	
	 /* Create the data and label array */
 	for ($i = 0; $i < count($xdata); $i++)
  	{
      	$xlabel[$i] = $xdata[$i][0];
     	$ydata[$i] = $xdata[$i][1];
  	}
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
  	$graph->title->Set("Proto Information");
  	$graph->Add($plot[0]);
  	$graph->Stroke(); 
?>