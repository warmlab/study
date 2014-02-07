#!/usr/bin/php -q
<?php
# use in ./<command> <src file/dir> [src file/dir ...] target_dir

function is_duplicated_photo($p1, $p2) {
	if (is_file($p1) and is_file($p2)) {
		$m1 = md5_file($p1);
		$m2 = md5_file($p2);

		if ($m1 === $m2) {
			return 0; # duplicate
		} else  {
			return 1; # not duplicate content, just duplicate file name.
		}
	}

	return 2;
}

function move_photo($photo, $target_path) {
	# get status about photo
	$status = stat($photo);
	#$tz_object = new DateTimeZone('Asia/Chongqing');
	$now = new DateTime();
	#$datetime->setTimeZone($tz_object);
	#$diff = $now->diff(new DateTime($mtime));
	$diff = $now->getTimestamp() - $status['mtime'];
	if ($diff < 24 * 60 * 60) # just move yesterday or former photo
		print "do not move file: $photo for it was not uploaded over 1 day.\n";
		return false;
	# get original time from exif
	$exif=exif_read_data($photo, "EXIF", true);
	if (!$exif) {
		return false;
	}

	if (!(array_key_exists("EXIF", $exif) and array_key_exists("DateTimeOriginal", $exif["EXIF"]))) {
		return false;
	}

	$original_time = $exif["EXIF"]["DateTimeOriginal"];

	# just get date
	$space_pos = strpos($original_time, ' ');
	$original_time = strtr(substr($original_time, 0, $space_pos), ':', '-') . substr($original_time, $space_pos);
	#$original_time = new DateTime(strtr($original_time, ':', '-'));
	$original_time = new DateTime($original_time);
	#$original_time->setTimeZone($tz_object);

	# create target directory if it is not exists.
	$path = $target_path . "/" . $original_time->format('Y/m/d/');
	if (is_writable($target_path)) {
		if (!(is_dir($path))) {
			$r = mkdir($path, 0755, true);
			if (!$r) {
				return $r;
			}
		}
		if (!is_writable($path)) {
			return false;
		}
	} else {
		if (!is_dir($path) or !is_writable($path)) {
			return false;
		}
	}

	# move file to target place
	$base_name = basename($photo);
	$ext_name = substr($base_name, strrpos($base_name, '.'));
	$target_photo = $path . $base_name;
	$base_name = substr($base_name, 0, strpos($base_name, '.'));
	$index = 1;
	while (true) {
		$r = is_duplicated_photo($photo, $target_photo);
		if ($r == 0) { # duplicate name and content
			#remove current photo
			print "remove duplicated file: \"$photo\".\n";
			$r = unlink($photo);
			break;
		} else if ($r == 1) { # duplicate name but not content
			# generete a new name for photo
			$target_photo = $path . $base_name . sprintf("_%03d", $index) . $ext_name;
			$index++;
		} else {
			# move photo to new place
			print "move photo from \"$photo\" to \"$target_photo\".\n";
			$r = rename($photo, $target_photo);
			break;
		}
	}

	return $r;
}

#$r = move_photo("/home/xli/Pictures/IMG_2133.JPG", "/home/xli/Pictures/");
#echo $r;
#$source_dir = "/home/xli/Pictures";

function scan_photo_dir($source_dir, $target_dir, $recursive=true) {
	$files = scandir($source_dir);
	foreach ($files as $file) {
		if ($file == '.' or $file == '..') {
		} else {
			$source_file = $source_dir . '/' . $file;
			if (is_dir($source_file)) {
				if ($recursive) {
					scan_photo_dir($source_file, $target_dir);
				}
			} else if (is_file($source_file)) {
				$ext = substr(strtolower($file), -4);
				if ($ext === '.jpg' or $ext === '.png') {
					move_photo($source_file, $target_dir);
					continue;
				}
				$ext = substr(strtolower($file), -5);
				if ($ext === '.jpeg' or $ext === '.tiff') {
					move_photo($source_file, $target_dir);
					continue;
				}
			}
		}
	}
}

if (count($argv) >= 3) {
	$target_dir = array_pop($argv);
	if (!is_dir($target_dir)) {
		print "$target_dir is not a directory\n";
	}
	foreach ($argv as $arg) {
		if (is_dir($arg)) {
			scan_photo_dir($arg, $target_dir);
		} else if (is_file($arg)) {
			$ext = substr(strtolower($arg), -4);
			if ($ext === '.jpg' or $ext === '.png') {
				move_photo($arg, $target_dir);
				continue;
			}
			$ext = substr(strtolower($arg), -5);
			if ($ext === '.jpeg' or $ext === '.tiff') {
				move_photo($arg, $target_dir);
				continue;
			}
		} else {
			print "$arg is not a file or directory\n";
		}
	}
}

?>
