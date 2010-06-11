<?php
/*  
 * Analysis Console for Intrusion Databases (ACID)
 *
 * Author: Roman Danyliw <rdd@cert.org>, <roman@danyliw.com>
 *
 * Copyright (C) 2001,2002 Carnegie Mellon University
 * (see the file 'acid_main.php' for license details)
 *
 * Purpose: Prints or generates HTML to display
 */

function PrintACIDSubHeader($page_title, $page_name, $back_link)
{
  GLOBAL $debug_mode, $ACID_VERSION, $html_no_cache, 
         $max_script_runtime;   

  if ( ini_get("safe_mode") != true )
     set_time_limit($max_script_runtime);

  echo '

<!doctype html public "-//w3c//dtd html 4.0 transitional//en">
<!-- Analysis Console for Incident Databases (ACID) '.$ACID_VERSION.' -->
<HTML>
  <HEAD>
    <META name="Author" content="Roman Danyliw">';

  if ( $html_no_cache == 1 )
     echo '<META HTTP-EQUIV="pragma" CONTENT="no-cache">';

  echo '
    <TITLE>ACID: '.$page_title.'</TITLE>
  <LINK rel="stylesheet" type="text/css" href="acid_style.css">

</HEAD>

<BODY>

<TABLE WIDTH="100%" BORDER=0 CELLSPACING=0 CELLPADDING=5>
<TR>
  <TD class="mainheader">';

  include("acid_hdr1.html");
  
  echo '
  </TD>
  <TD class="mainheadertitle">'.$page_name.'</TD>
  <TD class="mainheader" ALIGN=RIGHT>';
 
  include("acid_hdr2.html");
 
  echo '   
  </TD>

</TR>
</TABLE>';

  echo "<TABLE WIDTH=\"100%\"><TR><TD ALIGN=RIGHT>[&nbsp;".$back_link."&nbsp;]</TD></TR></TABLE><BR>";

  if ( $debug_mode > 0 )  PrintPageHeader();
}

function PrintACIDSubFooter()
{
  echo "\n\n<!-- ACID Footer -->\n".
       "<P>\n".
       "<TABLE WIDTH=\"100%\" BORDER=0 CELLSPACING=0 CELLPADDING=5>\n".
       " <TR>\n".
       "  <TD class=\"mainheader\">\n";

  include("acid_footer.html");

  echo "  </TD>\n".
       " </TR>\n".
       "</TABLE>\n\n".
       "</BODY>\n</HTML>\n";
}

      
function PrintFramedBoxHeader($title, $fore, $back)
{
  echo '
<TABLE WIDTH="100%" CELLSPACING=0 CELLPADDING=2 BORDER=0 BGCOLOR="'.$fore.'">
<TR><TD>
  <TABLE WIDTH="100%" CELLSPACING=0 CELLPADDING=2 BORDER=0 BGCOLOR="'.$back.'">
  <TR><TD class="sectiontitle">&nbsp;'.$title.'&nbsp;</TD></TR>
    <TR><TD>';
} 

function PrintFramedBoxFooter()
{
  echo '
  </TD></TR></TABLE>
</TD></TR></TABLE>';
}

function PrintFreshPage($refresh_stat_page, $stat_page_refresh_time)
{
   GLOBAL $HTTP_SERVER_VARS;

   if ( $refresh_stat_page )
      echo '<META HTTP-EQUIV="REFRESH" CONTENT="'.$stat_page_refresh_time.
           '"; URL="'.$HTTP_SERVER_VARS["PHP_SELF"].'";>'."\n";
}

function chk_select($stored_value, $current_value)
{
     if ( $stored_value == $current_value )
          return " SELECTED";
     else
          return " ";
}

function chk_check($stored_value, $current_value)
{
     if ( $stored_value == $current_value )
          return " CHECKED";
     else
          return " ";
}

?>
