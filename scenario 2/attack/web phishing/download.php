<?php
if (isset($_GET['file'])) {
    $file = basename($_GET['file']);
    $file_path = "/var/www/html/NT522/" . $file;

    if (file_exists($file_path)) {
        header('Content-Disposition: attachment; filename="' . $file . '"');
        $mime_type = mime_content_type($file_path);
        header('Content-Type: ' . $mime_type);
        readfile($file_path);
        exit;
    } else {
        http_response_code(404);
        echo "File not found";
    }
} else {
    http_response_code(400);
    echo "No file specified";
}
?>