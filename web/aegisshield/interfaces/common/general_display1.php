<?php 
	/*jpgraph������˵�ǰĿ¼��
	 *  Note:
	 *  	general_display.php equals to a img file. 
	 * 		So there should be no space between <?php ?>
	 * 		����<img>��ǩ��ʹ��ͼƬʱ�����ļ������õ��ļ�Ӧ�����
	 * 		���ļ���Ŀ¼
	 * 
	 * 
	 */

	require_once('../../includes/connection_settings.php');
	require_once('../../classes/adodb/adodb.inc.php');
	require_once('../../classes/graph_data_class.php');
	/*
	 * 
	 */
	//Create object
	$DB = NewADOConnection($_type_of_db_server);
	$_res_db = @$DB->Connect($_host, $_user, $_password, $_db_name);
	
	
	$GRAPH_DATA1 = new graph_data(&$DB);
	/*
	 * Lib
	 */
	
	$data = $GRAPH_DATA1->agTest();
	$min_size = 0;
	$GRAPH_DATA1->getSensorDataSet($xdata, "", $min_size, "");
	
	 /* Create the data and label array */
 	
 	 for ($i = 0; $i < count($xdata); $i++)
  	{
      	$xlabel[$i] = $xdata[$i][0];
     	$ydata[$i] = $xdata[$i][1];
  	}
	
	
	require_once('jpgraph/src/jpgraph.php');
	require_once('jpgraph/src/jpgraph_line.php');
	
	$width = $_GET['width'];
	$height = $_GET['height'];
	
	$chart_title = "Sensor vs. Number of Alerts";
    $xaxis_label = "Sensor";
    $yaxis_label = "Alert Occurrences";
		  

?>
<?php /*����jpgraph*/
	$GRAPH = new Graph($width, $height);
	
	$GRAPH->SetScale('intint');
	$GRAPH->title->Set($chart_title);
	$GRAPH->xaxis->title->Set($xaxis_label);
	$GRAPH->yaxis->title->Set($yaxis_label);
	//create the linera plot
	//$lineplot = new LinePlot($data);
	$lineplot = new LinePlot($ydata);
	//add the plot to the graph
	$GRAPH->Add($lineplot);
	//display the graph
	$GRAPH->Stroke();
?>