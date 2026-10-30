#!/usr/bin/env Rscript
# ============================================================
# 04_load_db.R — ЭТАП 3: загрузка очищенного корпуса в SQLite
#
# Что делает:
#   1) Читает corpus_tagged.csv (выход 03_nlp_pipeline.R);
#   2) заполняет sources и corpus_mentions (сырьё для линковки);
#   3) из УПОМИНАНИЙ формирует кандидатов инцидентов (event_date +
#      хотя бы один вектор) и загружает их в incidents / incident_vectors
#      со статусом review_status='pending' — ручная верификация C1–C4
#      обязательна перед использованием в статье (анти-галлюцинации).
#
# Идемпотентность: таблицы sources/corpus_mentions/incidents очищаются
# перед загрузкой; справочники (dict_*) не трогаются.
# Запуск: Rscript scripts/04_load_db.R
# ============================================================

this_file <- sub("^--file=.*scripts/", "", grep("^--file=", commandArgs(FALSE), value = TRUE)[1])
ROOT <- if (nzchar(Sys.getenv("PROJECT_ROOT"))) Sys.getenv("PROJECT_ROOT") else {
  a <- grep("^--file=", commandArgs(FALSE), value = TRUE)
  if (length(a)) dirname(dirname(sub("^--file=", "", a[1]))) else getwd()
}
source(file.path(ROOT, "scripts", "00_config.R"))

suppressPackageStartupMessages({library(DBI); library(RSQLite); library(dplyr); library(stringr)})

tagged_f <- file.path(PATHS$data_proc, "corpus_tagged.csv")
if (!file.exists(tagged_f)) stop("Нет corpus_tagged.csv — сначала выполните 03_nlp_pipeline.R")
tg <- read.csv(tagged_f, stringsAsFactors = FALSE, encoding = "UTF-8")
log_info("Загружено упоминаний: ", nrow(tg))

con <- dbConnect(SQLite(), DB_FILE)
on.exit(dbDisconnect(con))

tax <- read_taxonomy()
tax_ver <- tax$taxonomy_versions$taxonomy_version[nrow(tax$taxonomy_versions)]

## ---------- sources ---------------------------------------------------------
dbExecute(con, "DELETE FROM corpus_mentions"); dbExecute(con, "DELETE FROM sources")
src_df <- tg %>%
  distinct(url, publisher, date) %>%
  mutate(source_type = case_match(publisher,
               "CISA" ~ "advisory", "NASA" ~ "official_statement",
               .default = "news"),
         reliability = case_match(publisher,
               c("CISA","NASA") ~ "high",
               c("SpaceNews","The Record","DarkReading","SecurityWeek","BleepingComputer",
                 "TheHackersNews","KrebsOnSecurity","TheRegister_Science","ArsTechnica_Space",
                 "SpaceflightNow","SpaceSafetyMagazine","NASASpaceflight","PayloadSpace",
                 "SpaceWatchGlobal") ~ "medium",
               .default = "low"))
ins_src <- function(i) tryCatch(dbExecute(con, "INSERT OR IGNORE INTO sources
    (url,publisher,source_type,published_at,accessed_at,reliability,title)
    VALUES (?1,?2,?3,?4,?5,?6,?7)",
    params = list(src_df$url[i], src_df$publisher[i], src_df$source_type[i],
                  substr(src_df$date[i],1,10), DATA_CUTOFF_DATE,
                  src_df$reliability[i], NA_character_), silent = TRUE),
    error = function(e) NA_integer_)
invisible(lapply(seq_len(nrow(src_df)), ins_src))
n_src <- dbGetQuery(con, "SELECT COUNT(*) n FROM sources")$n
log_info("sources: ", n_src)

## ---------- corpus_mentions -------------------------------------------------
entities_json <- paste0('{"vectors":"', gsub('"', '', tg$vectors),
                        '","satellites":"', gsub('"', '', tg$satellites),
                        '","cves":"', tg$cves, '"}')
for (i in seq_len(nrow(tg))) {
  sid <- suppressWarnings(dbGetQuery(con, "SELECT source_id FROM sources WHERE url=?1",
                                    params = list(tg$url[i]))$source_id[1])
  try(dbExecute(con, "INSERT INTO corpus_mentions
      (source_id, raw_text, extracted_entities, nlp_pipeline_ver) VALUES (?1,?2,?3,?4)",
      params = list(sid, tg$text[i], entities_json[i], NLP_PIPELINE_VER), silent = TRUE),
      silent = TRUE)
}
log_info("corpus_mentions: ", dbGetQuery(con, "SELECT COUNT(*) n FROM corpus_mentions")$n)

## ---------- кандидаты в incidents ------------------------------------------
dbExecute(con, "DELETE FROM incident_vectors"); dbExecute(con, "DELETE FROM incidents")

`%||%` <- function(a, b) if (is.null(a) || length(a) == 0 || any(is.na(a[1]))) b else a
str_trunc <- function(s, n) ifelse(nzchar(s), str_sub(s, 1, n), s)

# event_date: явная дата из текста (ISO или «Month D, YYYY»), иначе месяц публикации
MONTHS <- c(january=1,february=2,march=3,april=4,may=5,june=6,july=7,august=8,
            september=9,october=10,november=11,december=12)
get_event_date <- function(txt, dates_found, pub) {
  d <- strsplit(as.character(dates_found), ";")[[1]]; d <- d[nzchar(d)]
  iso <- grep("^\\d{4}-\\d{2}-\\d{2}$", d, value = TRUE)
  if (length(iso)) return(c(iso[1], "exact"))
  m <- regmatches(d, regexec("(?i)(january|february|march|april|may|june|july|august|september|october|november|december)[ ,]+(\\d{1,2}),? (\\d{4})", d, perl = TRUE))
  m <- m[lengths(m) == 4]
  if (length(m)) { x <- m[[1]]
    return(c(sprintf("%s-%02d-%02d", x[4], MONTHS[[tolower(x[2])]], as.integer(x[3])), "exact")) }
  # fallback: дата публикации
  p <- substr(as.character(pub), 1, 7)
  if (grepl("^\\d{4}-\\d{2}", p)) return(c(paste0(p, "-01"), "month"))
  c(NA_character_, "approx")
}
# коды сегментов — из справочника таксономии (SEG-*)
guess_segment <- function(txt, sats) {
  if (str_detect(txt, "ground station|uplink|tt&c|teleport|mission control|control center")) "SEG-GS"
  else if (str_detect(txt, "\\bgps\\b|gnss|beidou|galileo|glonass|navigation")) "SEG-GROUND-OTHER"
  else if (str_detect(txt, "on.?board|software.*satellite|firmware|telemetry")) "SEG-SPACE"
  else if (str_detect(txt, "supply chain|vendor|backdoor.*(update|firmware)")) "SEG-SUPPLY"
  else if (str_detect(txt, "cubesat|cube sat|nanosat|iot")) "SEG-IOT"
  else if (str_detect(txt, "jam|interfer|transponder|downlink|broadcast|ku.?band|c.?band|vsat|starlink|satcom|internet")) "SEG-COMMS"
  else "SEG-COMMS"
}
seg_codes <- tax$dict_segment$segment_code
conf_map <- c("V-EXP" = "single_source", "V-MAL" = "single_source") # по умолчанию single_source

cand <- tg %>% filter(is_incident_candidate %in% c(TRUE, "TRUE"), nzchar(vector_codes))
log_info("Кандидатов в инциденты: ", nrow(cand))

year_of <- function(x) substr(as.character(x), 1, 4)
for (i in seq_len(nrow(cand))) {
  ed <- get_event_date(cand$text_norm[i], cand$dates_found[i], cand$date[i])
  seg <- guess_segment(cand$text_norm[i], cand$satellites[i])
  if (!(seg %in% seg_codes)) seg <- "SEG-COMMS"
  ref <- sprintf("INC-%s-%04d", ifelse(is.na(ed[1]), year_of(cand$date[i]), year_of(ed[1])), i)
  ok <- dbExecute(con, "INSERT OR IGNORE INTO incidents
     (external_ref,event_date,date_precision,title,summary,target_segment,
      impact_level,confidence,attribution,attribution_conf,taxonomy_version,
      inclusion_ok,review_status)
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,1,'pending')",
     params = list(ref, ed[1], ed[2], str_trunc(cand$text[i], 160),
                   str_trunc(cand$text[i], 500), seg, 2L,
                   ifelse(grepl("V-EXP|V-MAL", cand$vector_codes[i]), "single_source", "single_source"),
                   "unknown", "unknown", tax_ver))
  iid <- dbGetQuery(con, "SELECT incident_id FROM incidents WHERE external_ref=?1",
                    params = list(ref))$incident_id[1]
  if (!is.na(iid)) {
    vs <- strsplit(cand$vector_codes[i], ";")[[1]]
    for (v in unique(vs)) if (nzchar(v))
      try(dbExecute(con, "INSERT OR IGNORE INTO incident_vectors
          (incident_id, vector_code, is_primary) VALUES (?1,?2,?3)",
          params = list(iid, v, v == unique(vs)[1]), silent = TRUE), silent = TRUE)
  }
}
log_info("incidents (кандидаты, pending): ", dbGetQuery(con, "SELECT COUNT(*) n FROM incidents")$n)
log_info("Готово. Следующий шаг: ручная верификация C1–C4 -> review_status='approved'.")
