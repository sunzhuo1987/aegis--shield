<?php
  //require_once('interfaces/common/state_common.php');
  require_once('interfaces/common/output_html.php');

  /*
   * 表格的一些变量
   */
  $submit = $_POST["submit"];
  $height = $_POST["height"];
  $width = $_POST["width"];
  $chart_type = $_POST["chart_type"];
  $user_chart_title = $_POST["user_chart_title"];	
  $chart_interval = $_POST["chart_interval"];
  $chart_begin_hour = $_POST["chart_begin_hour"];
  $chart_begin_month = $_POST["chart_begin_month"];
  $chart_begin_day = $_POST["chart_begin_day"];
  $chart_begin_year = $_POST["chart_begin_year"];
  $chart_end_hour = $_POST["chart_end_hour"];
  $chart_end_month = $_POST["chart_end_month"];
  $chart_end_day = $_POST["chart_end_day"];
  $chart_end_year = $_POST["chart_end_year"];
  $chart_style = $_POST["chart_style"];
  $pmargin0 = $_POST["pmargin0"];
  $pmargin1 = $_POST["pmargin1"];
  $pmargin2 = $_POST["pmargin2"];
  $pmargin3 = $_POST["pmargin3"];
  

  $page_title = "Graph Alert Data";

?>
<?php

  /* Set default chart values */
  if ( $submit == "" )
  {
     $height = 400;
     $width = 600;
     $pmargin0 = 50;
     $pmargin1 = 50;
     $pmargin2 = 70;
     $pmargin3 = 80;
     $user_chart_title = "Aegisshield Chart";
     $min_size = 0;
     $rotate_xaxis_lbl = 0;
     $xaxis_label_inc = 1;
     $yaxis_scale = 0;
     $chart_style = "bar";
     $use_alerts = 0;
     $xaxis_grid = 0;
     $yaxis_grid = 1;
  }

  /*
   * 图表配置框
   */
  include("interfaces/common/graph_form.php");
  
  /*
   * 后面部分提交后显示
   */

  $data_pnt_cnt = 0;
 
  if ( $submit != "" && $chart_type == " " )
     echo '<FONT><B>No chart type was specified</B>.</FONT>';


  /* Calculate the data set */
  else if ($submit != "")
  {

     unset($xdata);
     unset($xlabel);
	
  /*
   * chart time begin
   */
  $time_begin[0] = $chart_begin_hour;
  $time_begin[1] =  $chart_begin_day;
  $time_begin[2] =  $chart_begin_month;
  $time_begin[3] = $chart_begin_year;


  /*
   * chart time end
   */
  $time_end[0] = $chart_end_hour;
  $time_end[1] = $chart_end_day;
  $time_end[2] =  $chart_end_month;
  $time_end[3] =  $chart_end_year;
	

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
         
         $data_pnt_cnt = $GRAPH_DATA->getTimeDataSet($xdata, $chart_type, $time_begin, $time_end);     
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

     if ( $data_pnt_cnt > 0 )
     {
   		/*
   		 * 
   		 */
        echo "<CENTER>
              <IMG SRC=\"interfaces/common/graph_display_".$chart_style.".php?width=$width&height=$height".
                      "&pmargin0=$pmargin0&pmargin1=$pmargin1".
                      "&pmargin2=$pmargin2&pmargin3=$pmargin3".
                      "&chart_type=$chart_type&chart_interval=$chart_interval".
        			  "&chart_begin_hour=$chart_begin_hour&chart_begin_month=$chart_begin_month&chart_begin_day=$chart_begin_day&chart_begin_year=$chart_begin_year".
        			  "&chart_end_hour=$chart_end_hour&chart_end_month=$chart_end_month&chart_end_day=$chart_end_day&chart_end_year=$chart_end_year".
        			  "\"></CENTER>";    
      }
      else
        echo 'No data !';
   }
?>