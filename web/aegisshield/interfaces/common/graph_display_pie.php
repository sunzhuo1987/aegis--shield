<?php
/*	动态显示图片
 *  line 图表
 */

  //include('state_common.php');
  
  require_once('../../includes/connection_settings.php');
  require_once('../../classes/adodb/adodb.inc.php');
  require_once('../../classes/graph_data_class.php');
  
  //Create object
  $DB = NewADOConnection($_type_of_db_server);
  $_res_db = @$DB->Connect($_host, $_user, $_password, $_db_name);
	
	
  $GRAPH_DATA = new graph_data(&$DB);
 

  $width = $_GET["width"];
  $height = $_GET["height"];
  $pmargin0 = $_GET["pmargin0"];
  $pmargin1 = $_GET["pmargin1"];
  $pmargin2 = $_GET["pmargin2"];
  $pmargin3 = $_GET["pmargin3"];
  $chart_type = $_GET["chart_type"];
  $chart_interval = $_GET["chart_interval"];
  
  $time_begin[0] = $_GET["chart_begin_hour"];
  $time_begin[1] = $_GET["chart_begin_day"];
  $time_begin[2] = $_GET["chart_begin_month"];
  $time_begin[3] = $_GET["chart_begin_year"];
  $time_end[0] = $_GET["chart_end_hour"];
  $time_end[1] = $_GET["chart_end_day"];
  $time_end[2] = $_GET["chart_end_month"];
  $time_end[3] = $_GET["chart_end_year"];
  
  
  /*
	 * 图表类型
	 */
   
  
  switch ($chart_type)
  {
     case 1:
     case 2:
     case 3:
     case 4:
     case 5:
     {
         $chart_title = "Time vs. Number of Alerts";
         $xaxis_label = "Time";
         $yaxis_label = "Alert Occurrences";
         
         $GRAPH_DATA->getTimeDataSet($xdata, $chart_type, $time_begin, $time_end);
         //$chart_title = $chart_title."\n ( ".$xdata[0][0]." - ".$xdata[count($xdata)-1][0]." )";
        
         break;
     }
     case 6:  // Src. IP vs. Num Alerts
     {
         $chart_title = "Source IP vs. Number of Alerts";
         $xaxis_label = "Source IP Address";
         $yaxis_label = "Alert Occurrences";

         
         $data_pnt_cnt = $GRAPH_DATA->getIpDataSet($xdata, $chart_type, $time_begin, $time_end);
         break;
        
     }
     case 7:  // Dst. IP vs. Num Alerts
     {
         $chart_title = "Destination IP vs. Number of Alerts";
         $xaxis_label = "Destination IP Address";
         $yaxis_label = "Alert Occurrences";
		
         $data_pnt_cnt = $GRAPH_DATA->getIpDataSet($xdata, $chart_type, $time_begin, $time_end);
        
         break;
      }
      case 8:  // UDP Port vs. Num Alerts 
      {
         $chart_title = "UDP Port (Destination) vs. Number of Alerts";
         $xaxis_label = "Dst. UDP Port";
         $yaxis_label = "Alert Occurrences";
	     
         $data_pnt_cnt = $GRAPH_DATA->getPortDataSet($xdata, $chart_type, $time_begin, $time_end);
         
         break;
      }
      case 10:  // UDP Port vs. Num Alerts 
      {
         $chart_title = "UDP Port (Source) vs. Number of Alerts";
         $xaxis_label = "Src. UDP Port";
         $yaxis_label = "Alert Occurrences";
	     
         $data_pnt_cnt = $GRAPH_DATA->getPortDataSet($xdata, $chart_type, $time_begin, $time_end);
         
         break;
       }
       case 9:  // TCP Port vs. Num Alerts 
       {
          $chart_title = "TCP Port (Destination) vs. Number of Alerts";
          $xaxis_label = "Dst. TCP Port";
          $yaxis_label = "Alert Occurrences";
			
          
          $data_pnt_cnt = $GRAPH_DATA->getPortDataSet($xdata, $chart_type, $time_begin, $time_end);
          
          break;
       }
       case 11:  // TCP Port vs. Num Alerts 
       {
          $chart_title = "TCP Port (Source) vs. Number of Alerts";
          $xaxis_label = "Src. TCP Port";
          $yaxis_label = "Alert Occurrences";
	      
          $data_pnt_cnt = $GRAPH_DATA->getPortDataSet($xdata, $chart_type, $time_begin, $time_end);
          
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
		  
           $data_pnt_cnt = $GRAPH_DATA->getSensorDataSet($xdata, $chart_type, $time_begin, $time_end);
           $chart_title = $chart_title."\n ( ".$time_begin[3]."-".$time_begin[2]."-".$time_begin[1]." - ".
           					$time_end[3]."-".$time_end[2]."-".$time_end[1]." )";
         
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
  
  
?>
<?php 
 /*
   * Jpgraph Lib
   */
  require_once('jpgraph/src/jpgraph.php');
  require_once('jpgraph/src/jpgraph_canvas.php');
  require_once('jpgraph/src/jpgraph_error.php');
  require_once('jpgraph/src/jpgraph_log.php');
  require_once('jpgraph/src/jpgraph_pie.php');
  require_once('jpgraph/src/jpgraph_pie3d.php');
  require_once('jpgraph/src/jpgraph_scatter.php');
  require_once('jpgraph/src/jpgraph_radar.php');
  
  
 
  $graph = new PieGraph($width, $height);
  
  /* Set Margins */
  $graph->img->SetMargin($pmargin0,$pmargin1,$pmargin2,$pmargin3);    
  $graph->img->SetAntiAliasing();

  //$graph->SetShadow();

 
  $plot[0] = new PiePlot3D($ydata);
  //$plot[0]->SetColor("#000000");
  $plot[0]->SetLegends($xlabel);
 

  //$plot[0]->ShowValue(true);
  //$plot[0]->SetShadow();

  /* Set Title */
  //$graph->title->SetFont(FF_COMIC,FS_NORMAL,18);
  $graph->title->Set($chart_title);
  $graph->Add($plot[0]);
  $graph->Stroke();
?>