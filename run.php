<?php

include 'vendor/autoload.php';

$config = include 'src/config.php';

$app = new \Kotarb\Push\Push($config);
$app->go();