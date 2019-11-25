###1. potrzebujesz kluczy VAPID

web-push generate-vapid-keys

###2. konfiguracja

src/config.php_default -> src/config.php
adres mailowy, klucz publiczny i prywatny z #1
subskrypcję wklejasz jako jsona po prostu
i treść wiadomości

###3. composer install

###4 leci

php run.php
