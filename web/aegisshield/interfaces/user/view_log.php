<h5><?php echo $admin[67]; ?></h5>
<?php
		echo '<table id="manage_log" class="default_table">'.$USER->get_log_list($_user_active['id']).'</table>';
?>