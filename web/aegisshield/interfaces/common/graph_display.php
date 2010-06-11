<?php
/*	动态显示图片
 *
 */

  //include('state_common.php');
  
  require_once('../../includes/connection_settings.php');
  require_once('../../classes/adodb/adodb.inc.php');
  require_once('../../classes/graph_data_class.php');
  
  //Create object
  $DB = NewADOConnection($_type_of_db_server);
  $_res_db = @$DB->Connect($_host, $_user, $_password, $_db_name);
	
	
  $GRAPH_DATA2 = new graph_data(&$DB);
  /*
   * Jpgraph Lib
   */
  require_once('jpgraph/src/jpgraph.php');
  require_once('jpgraph/src/jpgraph_line.php');
  require_once('jpgraph/src/jpgraph_bar.php');
  require_once('jpgraph/src/jpgraph_canvas.php');
  require_once('jpgraph/src/jpgraph_error.php');
  require_once('jpgraph/src/jpgraph_log.php');
  require_once('jpgraph/src/jpgraph_pie.php');
  require_once('jpgraph/src/jpgraph_pie3d.php');
  require_once('jpgraph/src/jpgraph_scatter.php');
  require_once('jpgraph/src/jpgraph_radar.php');


  $width = $_GET["width"];
  $height = $_GET["height"];
  $pmargin0 = $_GET["pmargin0"];
  $pmargin1 = $_GET["pmargin1"];
  $pmargin2 = $_GET["pmargin2"];
  $pmargin3 = $_GET["pmargin3"];
  $chart_type = $_GET["chart_type"];
  $chart_interval = $_GET["chart_interval"];
  
  $style = $_GET["style"];



  /*
	 * 图表类型
	 */
   
  
  switch ($chart_type)
  {
     case 0:
     {
     	$chart_title = "Just A Test";
     	$xaxis_label = "Test for x axis";
     	$yaxis_label = "Test for y axis";
     	$data_pnt_cnt = 1;
     	break;
     }
     case 1:
     case 2:
     case 3:
     case 4:
     case 5:
     {
         $chart_title = "Time vs. Number of Alerts";
         $xaxis_label = "Time";
         $yaxis_label = "Alert Occurrences";
         /*
         $data_pnt_cnt = $GRAPH_DATA->getTimeDataSet($xdata, $chart_type, $data_source, $min_size, $criteria);
         $chart_title = $chart_title."\n ( ".$xdata[0][0]." - ".$xdata[count($xdata)-1][0]." )";
         */
         break;
     }
     case 6:  // Src. IP vs. Num Alerts
     {
         $chart_title = "Source IP vs. Number of Alerts";
         $xaxis_label = "Source IP Address";
         $yaxis_label = "Alert Occurrences";

         /*
         $data_pnt_cnt = $GRAPH_DATA->getIpDataSet($xdata, $chart_type, $min_size, $criteria);
         break;
         */
     }
     case 7:  // Dst. IP vs. Num Alerts
     {
         $chart_title = "Destination IP vs. Number of Alerts";
         $xaxis_label = "Destination IP Address";
         $yaxis_label = "Alert Occurrences";
		 /*
         $data_pnt_cnt = $GRAPH_DATA->getIpDataSet($xdata, $chart_type, $min_size, $criteria);
         */
         break;
      }
      case 8:  // UDP Port vs. Num Alerts 
      {
         $chart_title = "UDP Port (Destination) vs. Number of Alerts";
         $xaxis_label = "Dst. UDP Port";
         $yaxis_label = "Alert Occurrences";
	     /*
         $data_pnt_cnt = $GRAPH_DATA->getPortDataSet($xdata, $chart_type, $min_size, $criteria);
         */
         break;
      }
      case 10:  // UDP Port vs. Num Alerts 
      {
         $chart_title = "UDP Port (Source) vs. Number of Alerts";
         $xaxis_label = "Src. UDP Port";
         $yaxis_label = "Alert Occurrences";
	     /*
         $data_pnt_cnt = $GRAPH_DATA->getPortDataSet($xdata, $chart_type, $min_size, $criteria);
         */
         break;
       }
       case 9:  // TCP Port vs. Num Alerts 
       {
          $chart_title = "TCP Port (Destination) vs. Number of Alerts";
          $xaxis_label = "Dst. TCP Port";
          $yaxis_label = "Alert Occurrences";
			
          /*
          $data_pnt_cnt = $GRAPH_DATA->getPortDataSet($xdata, $chart_type, $min_size, $criteria);
          */
          break;
       }
       case 11:  // TCP Port vs. Num Alerts 
       {
          $chart_title = "TCP Port (Source) vs. Number of Alerts";
          $xaxis_label = "Src. TCP Port";
          $yaxis_label = "Alert Occurrences";
	      /*
          $data_pnt_cnt = $GRAPH_DATA->getPortDataSet($xdata, $chart_type, $min_size, $criteria);
          */
          break;
       }
       case 12:  // Classification vs. Num Alerts 
       {
          $chart_title = "Signature Classification vs. Number of Alerts";
          $xaxis_label = "Classification";
          $yaxis_label = "Alert Occurrences";
	      /*
          $data_pnt_cnt = $GRAPH_DATA->getClassificationDataSet($xdata, $chart_type, $min_size, $criteria);
          */
          break;
       }
       case 13:  // Sensor vs. Num Alerts 
       {
           $chart_title = "Sensor vs. Number of Alerts";
           $xaxis_label = "Sensor";
           $yaxis_label = "Alert Occurrences";
		  
           $data_pnt_cnt = $GRAPH_DATA->getSensorDataSet($xdata, $chart_type, $min_size, $criteria);
         
           break;
       }
  }
  
  
  /*
   * $chart_interval = 0, 7, 24, 24X7
   */
  /*
  if ( $chart_interval ) {
  		
  		for ( $i = 0; $i < $chart_interval; $i++ ) {
        		$chart_array [$i][0] = $i;
        		$chart_array [$i][1] = 0;
  		}
  		
  		for ( $i = 0; $i < count ($xdata); $i++ ) {
        		$chart_array [ $i % $chart_interval ][1] += $xdata [$i][1];
  		}
  
  		$xdata = $chart_array;
  }

  $data_str = "";
  $data_lbl_str = "";
  $xaxis_label_inc = 1;
  for ( $i = 0; $i < count($xdata); $i++)
  {
         
       if ( ($i % $xaxis_label_inc ) != 0 )
             $xdata[$i][0] = "";
   }
	*/
  /* Create the data and label array */
  for ($i = 0; $i < count($xdata); $i++)
  {
      $xlabel[$i] = $xdata[$i][0];
      $ydata[$i] = $xdata[$i][1];
  }

  if ( $style == "pie" )
     $graph = new PieGraph($width, $height);
  else
     $graph = new Graph($width, $height);

  /* Set Margins */
  $graph->img->SetMargin($pmargin0,$pmargin1,$pmargin2,$pmargin3);    
  $graph->img->SetAntiAliasing();

  //$graph->SetShadow();

  /* Set Plot type */
  switch($style)
  {
     case "bar":
        $plot[0] = new BarPlot($ydata);
        break;
     case "pie":
        $plot[0] = new PiePlot3D($ydata);
        break;
     case "line":
        $plot[0] = new LinePlot($ydata);      
        break;
  }

  //$plot[0]->SetColor("#000000");

  if ( ($style == "bar") || ($style == "line") )
  {
     /* Set Scale */
     if ( $yaxis_scale == 1 )
        $graph->SetScale("textlog");
     else
        $graph->SetScale("textlin");

     $plot[0]->SetFillColor("#BE0505");
     //$plot[0]->SetFillColor($GLOBALS['chart_bar_color_default']);

     /* Set Gridlines */
     if ( $xaxis_grid == 1 )
        $graph->xgrid->Show(true);
     else
        $graph->xgrid->Show(false);

     if ( $yaxis_grid == 1 )
        $graph->ygrid->Show(true);
     else
        $graph->ygrid->Show(false);
  
     /* Set Axis Labels */
     $graph->xaxis->title->Set($xaxis_label);
     $graph->yaxis->title->Set($yaxis_label);


     //$graph->xaxis->SetFont(FF_ARIAL,FS_NORMAL,11);

     $graph->xaxis->SetTickLabels($xlabel);

     if ( $rotate_xaxis_lbl == 1 )
        $graph->xaxis->SetLabelAngle(90);
  }

  if ( $style == "pie" )
  {
     $plot[0]->SetLegends($xlabel);
  }

  //$plot[0]->ShowValue(true);
  //$plot[0]->SetShadow();

  /* Set Title */
  //$graph->title->SetFont(FF_COMIC,FS_NORMAL,18);
  $graph->title->Set($title);


  $graph->Add($plot[0]);

  $graph->Stroke();
?>