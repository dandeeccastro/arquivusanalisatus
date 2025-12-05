# Arquivus Analisatus

A simple CLI tool that checks for duplicate files inside a filesystem.

## Why?

Have you ever made a backup? And then that backup's backup? And back it up again as insurance? And then you realize you have three or more similar but not quite equal filesystems?

I haven't. But people I love have, and this was made to help them.

## Quick Start

- Clone this repo with `git clone git@github.com:dandeeccastro/arquivusanalisatus`
- `cd arquivusanalisatus`
- Create an .env file with TARGET_DIR set to the directory you want to scan
- `python main.py` and go grab a drink, it will take long...

## Usage

There's no mystery to it, just `python main.py` with .env properly set. After it runs, you'll have:
- A CSV file with each file's hash, so you can open it as a spreadsheet and check for duplicates
- It'll also print to stdout which files are duplicates!
