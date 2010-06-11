<?php
		if ($_POST['send']==$admin[35]){
			echo '<div class="submit_form">'.$USER->change_password($_user_active['id'], $_POST['password']).'</div>';
		}
		else{
?>

<h5><?php echo $admin[65]; ?></h5>
<form method="post" action="">
<table id="change_password" class="default_table">
<tr class="center"><td><input type="password" name="password" value="" /></td></tr>
<tr class="center"><td><input type="submit" name="send" value="<?php echo $admin[35]; ?>" /></td></tr>
</table>
</form>

<?php
		}
?>