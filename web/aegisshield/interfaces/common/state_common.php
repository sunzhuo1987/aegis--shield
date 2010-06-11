<?php
/*  
 * Analysis Console for Intrusion Databases (ACID)
 *
 * Author: Roman Danyliw <rdd@cert.org>, <roman@danyliw.com>
 *
 * Copyright (C) 2000-2002 Carnegie Mellon University
 * (see the file 'acid_main.php' for license details)
 *
 * Purpose: routines to manipulate shared state (session
 *          information)   
 *
 */
/* ***********************************************************************
 * Function: InitArray()
 *
 * @doc Defines an initializes a 1 or 2 dimensional PHP array.
 *
 * @param $a      (in/out) array to initialize
 * @param $dim1   number of elements of first dimension
 * @param $dim2   number of elements of second dimension
 * @param $value  default value
 *
 ************************************************************************/
function InitArray(&$a, $dim1, $dim2, $value)
{
   $a = "";
   /* determine the number of dimensions in the array */
   if ( $dim2 == 0 )   /* 1-dim */
      for ( $i = 0; $i < $dim1; $i++ ) 
         $a[$i] = $value;
   else                /* 2-dim */
      for ( $i = 0; $i < $dim1; $i++ )
         for ( $j = 0; $j < $dim2; $j++ )
            $a[$i][$j] = $value;
}

/* ***********************************************************************
 * Function: RegisterGlobalState()
 *
 * @doc Application-specific wrapper for PHP session_start().  It performs
 *      a couple of additional configuration checks (notably for custom
 *      PHP session handlers).
 *
 ************************************************************************/
function RegisterGlobalState()
{
   /* Deal with user specified session handlers */
   if (session_module_name() == "user" )
   {
      if ( $GLOBALS['use_user_session'] != 1 )
      {
         ErrorMessage("PHP ERROR: A custom (user) PHP session have been detected. However, ACID has not been ".
                      "set to explicitly use this custom handler.  Set <CODE>use_user_session=1</CODE> in ".
                      "<CODE>acid_conf.php</CODE>");
         die();
      }
      else if ( $GLOBALS['user_session_path'] != "" )
      {
         if ( is_file($GLOBALS['user_session_path']) )
         {
            include_once($GLOBALS['user_session_path']);
            if ( $GLOBALS['user_session_function'] != "" )
               $GLOBALS['user_session_function']();
         }
         else
         {
            ErrorMessage("PHP ERROR: A custom (user) PHP session hander has been configured, but the supplied ".
                         "hander code specified in <CODE>user_session_path</CODE> is invalid.");
            die();
         }
      }
      else
      {
         ErrorMessage("PHP ERROR: A custom (user) PHP session handler has been configured, but the implementation ".
                      "of this handler has not been specified in ACID.  If a custom session handler is desired, ".
                      "set the <CODE>user_session_path</CODE> variable in <CODE>acid_conf.php</CODE>.");
         die();
      }
   }

   session_start();

   if ( $GLOBALS['debug_mode'] > 0 )
      echo '<FONT COLOR="#FF0000">Session Registered</FONT><BR>';
}

/* ***********************************************************************
 * Function: CleanVariables()
 *
 * @doc Removes invalid characters/data from a variable based on a
 *      specified mask of acceptable data or a list of explicit values.
 *
 *      Note: only the mask or explicit list can be used a a time
 *
 * @param item        variable to scrub
 * @param valid_data  mask of valid characters
 * @param exception   array with explicit values to match
 *
 * @return a sanitized version of the passed variable
 *
 ************************************************************************/
function CleanVariable($item, $valid_data, $exception = "")
{
   return $item;

   /* Check the exception value list first */
   if ( $exception != "" )
   {
      if ( in_array($item, $exception) )
         return $item;
      else
         return "";
   }

   if ( $valid_data == "" )
      return $item;

   $regex_mask = "";

   if ( ($valid_data & VAR_DIGIT) > 0 )
      $regex_mask = $regex_mask . "0-9";

   if ( ($valid_data & VAR_LETTER) > 0 )
      $regex_mask = $regex_mask . "A-Za-z";

   if ( ($valid_data & VAR_ULETTER) > 0 ) 
      $regex_mask = $regex_mask . "A-Z";

   if ( ($valid_data & VAR_LLETTER) > 0 ) 
      $regex_mask = $regex_mask . "a-z";

   if ( ($valid_data & VAR_ALPHA) > 0 ) 
      $regex_mask = $regex_mask . "0-9A-Za-z";

   if ( ($valid_data & VAR_SPACE) > 0 ) 
      $regex_mask = $regex_mask . "\ ";

   if ( ($valid_data & VAR_PERIOD) > 0 ) 
      $regex_mask = $regex_mask . "\.";

   if ( ($valid_data & VAR_OPAREN) > 0 ) 
      $regex_mask = $regex_mask . "\(";

   if ( ($valid_data & VAR_CPAREN) > 0 ) 
      $regex_mask = $regex_mask . "\)";

   if ( ($valid_data & VAR_BOOLEAN) > 0 ) 
      $regex_mask = $regex_mask . "\)";

   if ( ($valid_data & VAR_OPERATOR) > 0 ) 
      $regex_mask = $regex_mask . "\)";

   if ( ($valid_data & VAR_PUNC) > 0 ) 
      $regex_mask = $regex_mask . "\!\#\$\%\^\&\*\_\-\=\+\:\;\,\?\ \(\))";

   if ( ($valid_data & VAR_USCORE) > 0 ) 
      $regex_mask = $regex_mask . "\_";

   if ( ($valid_data & VAR_AT) > 0 ) 
      $regex_mask = $regex_mask . "\@";

   return ereg_replace("[^".$regex_mask."]", "", $item);
}

/* ***********************************************************************
 * Function: SetSessionVar()
 *
 * @doc Handles retrieving and updating persistant session (criteria)
 *      data.  This routine handles the details of checking for criteria
 *      updates passed through POST/GET and resolving this with values
 *      that may already have been set and stored in the session.
 *
 *      All criteria variables need invoke this function before they are 
 *      used for the first time to extract their previously stored values,
 *      and process potential updates to their value.
 *
 *      Note: Validation of user input is not performed by this routine.
 *     
 * @param $var_name  name of the persistant session variable to retrieve
 *
 * @return the updated value of the persistant session variable named
 *         by $var_name
 *
 ************************************************************************/
function SetSessionVar($var_name)
{
   GLOBAL $HTTP_POST_VARS, $HTTP_GET_VARS, $HTTP_SESSION_VARS;

   if ( isset($HTTP_POST_VARS[$var_name]) ) 
   {
      if ( $GLOBALS['debug_mode'] > 0 )  echo "importing POST var '$var_name'<BR>";
      return $HTTP_POST_VARS[$var_name];
   }
   else if ( isset($HTTP_GET_VARS[$var_name]) )
   { 
      if ( $GLOBALS['debug_mode'] > 0 )  echo "importing GET var '$var_name'<BR>";
      return $HTTP_GET_VARS[$var_name];
   }
   else if ( isset($HTTP_SESSION_VARS[$var_name]) )
   { 
      if ( $GLOBALS['debug_mode'] > 0 )  echo "importing SESSION var '$var_name'<BR>";
      return $HTTP_SESSION_VARS[$var_name];
   }
   else
      return "";
}

/* ***********************************************************************
 * Function: ImportHTTPVar()
 *
 * @doc Handles retrieving temporary state variables needed to present a 
 *      given set of results (e.g., sort order, current record).  The
 *      values of these variables are never persistantly stored.  Rather,
 *      they are passed as HTTP POST and GET parameters.
 *
 *      All temporary variables need invoke this function before they are 
 *      used for the first time to extract their value.
 *
 *      Optionally, sanitization parameters can be set, ala CleanVariable()
 *      syntax to validate the user input.
 *     
 * @param $var_name     name of the temporary state variable to retrieve
 * @param $valid_data   (optional) list of valid character types 
 *                                 (see CleanVariable)
 * @param $exception    (optional) array of explicit values the imported
 *                      variable must be set to
 * 
 * @see CleanVariable
 *
 * @return the sanitized value of the temporary state variable named
 *         by $var_name
 *
 ************************************************************************/
function ImportHTTPVar($var_name, $valid_data = "", $exception = "")
{
   GLOBAL $HTTP_POST_VARS, $HTTP_GET_VARS, $debug_mode;

   $tmp = "";

   if ( isset($HTTP_POST_VARS[$var_name]) ) 
   {
      //if ( $debug_mode > 0 )  echo "importing POST var '$var_name'<BR>";
      $tmp = $HTTP_POST_VARS[$var_name];
   }
   else if ( isset($HTTP_GET_VARS[$var_name]) )
   { 
      //if ( $debug_mode > 0 )  echo "importing GET var '$var_name'<BR>";
      $tmp = $HTTP_GET_VARS[$var_name];
   }
   else
      $tmp = "";

   return CleanVariable($tmp, $valid_data, $exception);
}

/* ***********************************************************************
 * Function: ExportHTTPVar()
 *
 * @doc Handles export of a temporary state variables needed to present a 
 *      given set of results (e.g., sort order, current record).  This
 *      routine creates a hidden HTML form variable.
 *
 *      Note: The user is responsible for generating the appropriate HTML
 *            form code.
 *
 *      Security Note: Only, temporary variables should make use of this 
 *                     function. These values are exposed in HTML to the 
 *                     user; he is free to modify them.
 * 
 * @param $var_name     name of the temporary state variable to export
 * @param $var_value   value of the temporary state variable
 *
 * @see ImportHTTPVar
 *
 ************************************************************************/
function ExportHTTPVar ($var_name, $var_value)
{
  echo "<INPUT TYPE=\"hidden\" NAME=\"$var_name\" VALUE=\"$var_value\">\n";
}
?>