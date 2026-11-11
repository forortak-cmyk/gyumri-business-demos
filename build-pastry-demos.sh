#!/bin/sh
set -eu
mkdir -p pastry-public
for site in caramel-cakes red-velvet-bakery luna-sweets gyumri-candy arpi-jelly dada-sweets; do
  mkdir -p "pastry-public/$site"
  for file in "$site"/*.html "$site"/*.css "$site"/*.js "$site"/*.svg; do
    if [ -f "$file" ]; then cp "$file" "pastry-public/$site/"; fi
  done
  if [ -d "$site/assets" ]; then cp -R "$site/assets" "pastry-public/$site/"; fi
done
cp pastry-index.html pastry-public/index.html
