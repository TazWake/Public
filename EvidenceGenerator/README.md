# Evidence Generator.

## Workflow

- Ensure you have the three source files
- Run the python scripts
- Clean the access log with `grep -Ev '^(0\.(0|1|2|3|4|5|6|7|8|9)|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|100\..*|127\..*|169\.254\.169\.254|192\.0\.2\.|192\.88\.99\.|198\.18\.|198\.51\.100\.|203\.0\.113\.|224\.0\.0\.|240\.0\.0\.|255\.255\.255\.255)' fake_access_log.txt > filtered_access_log.txt`
- Rename the files as needed
