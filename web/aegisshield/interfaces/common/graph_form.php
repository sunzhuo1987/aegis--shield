<?php
/*  
 * Purpose:  displays form for graphing
 */

  echo '<FORM ACTION="admin.php?action=view_logs" METHOD="post">';

  echo '<TABLE WIDTH="100%" BORDER=2 BGCOLOR="#CCCC99">
          <TR>
           <TD COLSPAN=2>';

  echo '<B>Chart Title:</B> &nbsp;
            <INPUT TYPE="text" NAME="user_chart_title" SIZE=60 VALUE="'.$user_chart_title.'"><BR>'; 
        
  echo '<B>Chart Type:</B>  &nbsp;
        <SELECT NAME="chart_type">
         <OPTION VALUE=" "  '.chk_select($chart_type, " ").'>{ chart type }
         <OPTION VALUE="1" '.chk_select($chart_type, "1").'>Time (hour) vs. Number of Alerts
         <OPTION VALUE="2" '.chk_select($chart_type, "2").'>Time (day) vs. Number of Alerts
         <OPTION VALUE="4" '.chk_select($chart_type, "4").'>Time (month) vs. Number of Alerts
         <OPTION VALUE="5" '.chk_select($chart_type, "5").'>Time (year) vs. Number of Alerts
         <OPTION VALUE="6" '.chk_select($chart_type, "6").'>Src. IP address vs. Number of Alerts
         <OPTION VALUE="7" '.chk_select($chart_type, "7").'>Dst. IP address vs. Number of Alerts
         <OPTION VALUE="8" '.chk_select($chart_type, "8").'>Dst. UDP Port vs. Number of Alerts
         <OPTION VALUE="10" '.chk_select($chart_type, "10").'>Src. UDP Port vs. Number of Alerts
         <OPTION VALUE="9" '.chk_select($chart_type, "9").'>Dst. TCP Port vs. Number of Alerts
         <OPTION VALUE="11" '.chk_select($chart_type, "11").'>Src. TCP Port vs. Number of Alerts
         <OPTION VALUE="13" '.chk_select($chart_type, "13").'>Sensor vs. Number of Alerts
        </SELECT>';

  echo '&nbsp;&nbsp;<B>Size: (width x height)</B>
        &nbsp;<INPUT TYPE="text" NAME="width" SIZE=4 VALUE="'.$width.'">
        &nbsp;<B>x</B>
        &nbsp;<INPUT TYPE="text" NAME="height" SIZE=4 VALUE="'.$height.'">
        &nbsp;&nbsp;<BR>';

  echo '&nbsp;&nbsp;<B>Plot Margins: (left x right x top x bottom)</B>
        &nbsp;<INPUT TYPE="text" NAME="pmargin0" SIZE=4 VALUE="'.$pmargin0.'">
        &nbsp;<B>x</B>
        &nbsp;<INPUT TYPE="text" NAME="pmargin1" SIZE=4 VALUE="'.$pmargin1.'">
        &nbsp;<B>x</B>
        &nbsp;<INPUT TYPE="text" NAME="pmargin2" SIZE=4 VALUE="'.$pmargin2.'">
        &nbsp;<B>x</B>
        &nbsp;<INPUT TYPE="text" NAME="pmargin3" SIZE=4 VALUE="'.$pmargin3.'">
        &nbsp;&nbsp;<BR>';

  echo '&nbsp;&nbsp;<B>Plot type:</B> &nbsp;&nbsp;
            <INPUT TYPE="radio" NAME="chart_style" 
                   VALUE="bar" '.chk_check($chart_style, "bar").'> bar &nbsp;&nbsp
            <INPUT TYPE="radio" NAME="chart_style" 
                   VALUE="line" '.chk_check($chart_style, "line").'> line &nbsp;&nbsp
            <INPUT TYPE="radio" NAME="chart_style" 
                   VALUE="pie" '.chk_check($chart_style, "pie").'> pie ';

  echo '<br><b>Chart Begin:</B>&nbsp;
        <SELECT NAME="chart_begin_hour">
         <OPTION VALUE=" "  '.chk_select($chart_begin_hour, " ").'>{hour}'."\n";
  echo  '<OPTION VALUE="00" '.chk_select($chart_begin_hour, "00").'>0
  		 <OPTION VALUE="01" '.chk_select($chart_begin_hour, "01").'>1
  		 <OPTION VALUE="02" '.chk_select($chart_begin_hour, "02").'>2
  		 <OPTION VALUE="03" '.chk_select($chart_begin_hour, "03").'>3
  	     <OPTION VALUE="04" '.chk_select($chart_begin_hour, "04").'>4
  		 <OPTION VALUE="05" '.chk_select($chart_begin_hour, "05").'>5
 		 <OPTION VALUE="06" '.chk_select($chart_begin_hour, "06").'>6
 		 <OPTION VALUE="07" '.chk_select($chart_begin_hour, "07").'>7
 		 <OPTION VALUE="08" '.chk_select($chart_begin_hour, "08").'>8
 		 <OPTION VALUE="09" '.chk_select($chart_begin_hour, "09").'>9';
        for ( $i = 10; $i <= 23; $i++ )
            echo "<OPTION VALUE=\"$i\" ".chk_select($chart_begin_hour, $i)." >$i\n";

  echo '</SELECT>
        <SELECT NAME="chart_begin_day">
         <OPTION VALUE=" "  '.chk_select($chart_begin_day, " ").'>{day}'."\n";
  echo 	'<OPTION VALUE="01" '.chk_select($chart_begin_day, "01").'>1
  		 <OPTION VALUE="02" '.chk_select($chart_begin_day, "02").'>2
  		 <OPTION VALUE="03" '.chk_select($chart_begin_day, "03").'>3
  	     <OPTION VALUE="04" '.chk_select($chart_begin_day, "04").'>4
  		 <OPTION VALUE="05" '.chk_select($chart_begin_day, "05").'>5
 		 <OPTION VALUE="06" '.chk_select($chart_begin_day, "06").'>6
 		 <OPTION VALUE="07" '.chk_select($chart_begin_day, "07").'>7
 		 <OPTION VALUE="08" '.chk_select($chart_begin_day, "08").'>8
 		 <OPTION VALUE="09" '.chk_select($chart_begin_day, "09").'>9';
        for ( $i = 10; $i <= 31; $i++ )
            echo "<OPTION VALUE=\"$i\" ".chk_select($chart_begin_day, $i).">$i\n";

  echo '</SELECT>
        <SELECT NAME="chart_begin_month">
         <OPTION VALUE=" "  '.chk_select($chart_begin_month, " ").'>{month}
         <OPTION VALUE="01" '.chk_select($chart_begin_month, "01").'>January
         <OPTION VALUE="02" '.chk_select($chart_begin_month, "02").'>February
         <OPTION VALUE="03" '.chk_select($chart_begin_month, "03").'>March
         <OPTION VALUE="04" '.chk_select($chart_begin_month, "04").'>April
         <OPTION VALUE="05" '.chk_select($chart_begin_month, "05").'>May
         <OPTION VALUE="06" '.chk_select($chart_begin_month, "06").'>June
         <OPTION VALUE="07" '.chk_select($chart_begin_month, "07").'>July
         <OPTION VALUE="08" '.chk_select($chart_begin_month, "08").'>August
         <OPTION VALUE="09" '.chk_select($chart_begin_month, "09").'>September
         <OPTION VALUE="10" '.chk_select($chart_begin_month, "10").'>October
         <OPTION VALUE="11" '.chk_select($chart_begin_month, "11").'>November
         <OPTION VALUE="12" '.chk_select($chart_begin_month, "12").'>December
        </SELECT>
        <SELECT NAME="chart_begin_year">
        <OPTION VALUE=" " '.chk_select($chart_begin_year, " ").'>{year}
        <OPTION VALUE="2010" '.chk_select($chart_begin_year, "2010").'>2010
        
        </SELECT>';

  echo '<br><b>Chart End:</B>&nbsp;&nbsp;&nbsp;&nbsp;
        <SELECT NAME="chart_end_hour">
         <OPTION VALUE=" "  '.chk_select($chart_end_hour, " ").'>{hour}'."\n";
  echo  '<OPTION VALUE="00" '.chk_select($chart_end_hour, "00").'>0
  		 <OPTION VALUE="01" '.chk_select($chart_end_hour, "01").'>1
  		 <OPTION VALUE="02" '.chk_select($chart_end_hour, "02").'>2
  		 <OPTION VALUE="03" '.chk_select($chart_end_hour, "03").'>3
  	     <OPTION VALUE="04" '.chk_select($chart_end_hour, "04").'>4
  		 <OPTION VALUE="05" '.chk_select($chart_end_hour, "05").'>5
 		 <OPTION VALUE="06" '.chk_select($chart_end_hour, "06").'>6
 		 <OPTION VALUE="07" '.chk_select($chart_end_hour, "07").'>7
 		 <OPTION VALUE="08" '.chk_select($chart_end_hour, "08").'>8
 		 <OPTION VALUE="09" '.chk_select($chart_end_hour, "09").'>9';
        for ( $i = 10; $i <= 23; $i++ )
           echo "<OPTION VALUE=$i ".chk_select($chart_end_hour, $i).">$i\n";

  echo '</SELECT>
        <SELECT NAME="chart_end_day">
         <OPTION VALUE=" "  '.chk_select($chart_end_day, " ").'>{day}'."\n";
  echo 	'<OPTION VALUE="01" '.chk_select($chart_end_day, "01").'>1
  		 <OPTION VALUE="02" '.chk_select($chart_end_day, "02").'>2
  		 <OPTION VALUE="03" '.chk_select($chart_end_day, "03").'>3
  	     <OPTION VALUE="04" '.chk_select($chart_end_day, "04").'>4
  		 <OPTION VALUE="05" '.chk_select($chart_end_day, "05").'>5
 		 <OPTION VALUE="06" '.chk_select($chart_end_day, "06").'>6
 		 <OPTION VALUE="07" '.chk_select($chart_end_day, "07").'>7
 		 <OPTION VALUE="08" '.chk_select($chart_end_day, "08").'>8
 		 <OPTION VALUE="09" '.chk_select($chart_end_day, "09").'>9';
        for ( $i = 10; $i <= 31; $i++ )
           echo "<OPTION VALUE=$i ".chk_select($chart_end_day, $i).">$i\n";

  echo '</SELECT>
        <SELECT NAME="chart_end_month">
         <OPTION VALUE=" "  '.chk_select($chart_end_month, " ").'>{month}
         <OPTION VALUE="01" '.chk_select($chart_end_month, "01").'>January
         <OPTION VALUE="02" '.chk_select($chart_end_month, "02").'>February
         <OPTION VALUE="03" '.chk_select($chart_end_month, "03").'>March
         <OPTION VALUE="04" '.chk_select($chart_end_month, "04").'>April
         <OPTION VALUE="05" '.chk_select($chart_end_month, "05").'>May
         <OPTION VALUE="06" '.chk_select($chart_end_month, "06").'>June
         <OPTION VALUE="07" '.chk_select($chart_end_month, "07").'>July
         <OPTION VALUE="08" '.chk_select($chart_end_month, "08").'>August
         <OPTION VALUE="09" '.chk_select($chart_end_month, "09").'>September
         <OPTION VALUE="10" '.chk_select($chart_end_month, "10").'>October
         <OPTION VALUE="11" '.chk_select($chart_end_month, "11").'>November
         <OPTION VALUE="12" '.chk_select($chart_end_month, "12").'>December
        </SELECT>
        <SELECT NAME="chart_end_year">
        <OPTION VALUE=" " '.chk_select($chart_end_year, " ").'>{year}
        <OPTION VALUE="2010" '.chk_select($chart_end_year, "2010").'>2010
       
        </SELECT>';

  echo '<INPUT TYPE="submit" NAME="submit" VALUE="Graph Alerts"><BR>
        &nbsp;&nbsp; <BR>
        </TD></TR>';

 
  echo '</TABLE>';

  echo '</FORM><P><HR>';

?>