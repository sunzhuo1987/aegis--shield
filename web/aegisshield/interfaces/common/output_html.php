<?php      
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
