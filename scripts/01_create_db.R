#!/usr/bin/env Rscript
# ============================================================
# 01_create_db.R — ЭТАП 1: создание SQLite-БД по схеме db/schema.sql
#                 и загрузка справочников таксономии из taxonomy/*.csv
# Запуск:  Rscript scripts/01_create_db.R [--fresh]
#   --fresh — пересоздать БД с нуля (идемпотентность сборки проекта)
# ============================================================

# Надёжное определение каталога скрипта (работает при Rscript scripts/01_... и из любого cwd)
this_file <- sub("^--file=", "", grep("^--file=", commandArgs(FALSE), value = TRUE)[1])
if (is.na(this_file) || !nzchar(this_file)) this_file <- "scripts/01_create_db.R"
source(file.path(dirname(this_file), "00_config.R"))

args     <- commandArgs(trailingOnly = TRUE)
fresh    <- "--fresh" %in% args

if (fresh && file.exists(DB_FILE)) {
  unlink(DB_FILE); log_info("Удалена старая БД: ", DB_FILE)
}

con <- DBI::dbConnect(RSQLite::SQLite(), DB_FILE)
DBI::dbExecute(con, "PRAGMA foreign_keys = ON;")

## 1. Схема ------------------------------------------------------------
schema_sql <- paste(readLines(file.path(ROOT, "db", "schema.sql"), encoding = "UTF-8"),
                    collapse = "\n")
# выполняем по операторам (SQLite не любит пустые фрагменты между ';')
stmts <- Filter(function(s) grepl("\\S", s), strsplit(schema_sql, ";\\s*\n")[[1]])
invisible(lapply(stmts, function(s) DBI::dbExecute(con, s)))
log_info("Схема загружена: таблиц = ",
         nrow(DBI::dbGetQuery(con, "SELECT name FROM sqlite_master WHERE type='table'")))

## 2. Справочники таксономии -------------------------------------------
tax <- read_taxonomy()

load_dict <- function(tab_name, df) {
  DBI::dbWriteTable(con, tab_name, df, append = TRUE)
}
# append может дублировать PK -> используем INSERT OR REPLACE через SQL
upsert_dict <- function(tab_name, df, pk) {
  for (i in seq_len(nrow(df))) {
    cols <- names(df); vals <- unlist(df[i, ])
    sql <- sprintf("INSERT OR REPLACE INTO %s (%s) VALUES (%s)",
                   tab_name,
                   paste(cols, collapse = ", "),
                   paste(DBI::dbQuoteString(con, as.character(vals)), collapse = ", "))
    DBI::dbExecute(con, sql)
  }
  log_info(sprintf("  %-18s строк: %d", tab_name, nrow(df)))
}

log_info("Загрузка справочников (таксономия v", TAXONOMY_VERSION, "):")
upsert_dict("dict_segment",    tax$dict_segment,    "segment_code")
upsert_dict("dict_vector",     tax$dict_vector,     "vector_code")
upsert_dict("dict_orbit",      tax$dict_orbit,      "orbit_code")
upsert_dict("dict_sat_type",   tax$dict_sat_type,   "sat_type_code")
upsert_dict("dict_confidence", tax$dict_confidence, "confidence_code")
upsert_dict("taxonomy_versions", tax$taxonomy_versions, "taxonomy_version")

## 3. Самопроверки ------------------------------------------------------
stopifnot(
  DBI::dbExistsTable(con, "incidents"),
  DBI::dbExistsTable(con, "v_incidents_enriched"),
  nrow(DBI::dbGetQuery(con, "SELECT * FROM dict_vector")) >= 12,
  any(DBI::dbGetQuery(con, "SELECT taxonomy_version FROM taxonomy_versions")$taxonomy_version
      == TAXONOMY_VERSION)
)
log_info("БД готова: ", DB_FILE)
DBI::dbDisconnect(con)
