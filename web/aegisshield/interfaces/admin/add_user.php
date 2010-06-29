<?php
if ($_POST['send']==$admin[397]){
		$user_array=array('username'=>$_POST['username'], 'passwd'=>$_POST['passwd'], 'privilege'=>$_POST['privilege'], 'name'=>$_POST['name'], 'surname'=>$_POST['surname'],  'email'=>$_POST['email'], );
		
		echo '<div class="submit_form">'.$USER->add_user($user_array).'</div>';
}
else{
?>

<h4><?php echo $admin[310]; ?></h4>
<form method="post" action="">
<table id="add_user" class="default_table">
  <tr>
    <td><?php echo $admin[390]; ?> * </td>
    <td><input type="text" name="name" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[391]; ?> * </td>
    <td><input type="text" name="surname" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[392]; ?> * </td>
    <td><input type="text" name="username" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[340]; ?> * </td>
    <td><input type="text" name="passwd" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[393]; ?> * </td>
    <td><input type="text" name="email" /></td>
  </tr>

  <tr>
    <td><?php echo $admin[394]; ?> * </td>
    <td><?php echo $USER->privilege_list(); ?></td>
  </tr>
  <tr>
    <td>&nbsp;</td>
    <td><input type="submit" name="send" value="<?php echo $admin[397]; ?>" /></td>
  </tr>
</table>
</form>
<br />
<div class="center">* <?php echo $admin[398]; ?><br />
** <?php echo $admin[399]; ?></div>
<?php 
}
?>