#!/usr/bin/env Rscript
# ============================================================
# 03_nlp_pipeline.R — ЭТАП 2: очистка и NLP-разметка корпуса
#
# Пайплайн (реализован на base R + stringr, без тяжёлых зависимостей;
# архитектура совместима с заменой на tidytext/quanteda):
#   1) Токенизация предложений/слов
#   2) Словарно-регулярный NER: названия КА/систем, операторы, векторы, CVE, даты, GEO
#   3) Классификация по таксономии v1.0.0 (вектор -> коды dict_vector)
#   4) Кандидатная оценка «инцидентность» (фильтр против новостного шума)
#   5) Дедупликация по нормализованному заголовку
# Выход: data/processed/corpus_tagged.csv  (кандидаты для ручного отбора в БД!)
#
# ВАЖНО (анти-галлюцинации): скрипт НЕ создаёт инциденты. Он только
# помечает УПОМИНАНИЯ; в incidents попадают лишь события, вручную
# подтверждённые оператором по критериям C1–C4 (см. docs/TAXONOMY.md).
#
# Запуск: Rscript scripts/03_nlp_pipeline.R
# ============================================================

this_file <- sub("^--file=", "", grep("^--file=", commandArgs(FALSE), value = TRUE)[1])
if (is.na(this_file) || !nzchar(this_file)) this_file <- "scripts/03_nlp_pipeline.R"
source(file.path(dirname(this_file), "00_config.R"))

suppressWarnings(library(stringr))

## ---------- 1. Вход: собранные упоминания ----------------------------------
mentions <- data.frame(text = character(), url = character(), date = character(),
                        publisher = character(), stringsAsFactors = FALSE)

gdelt_f <- file.path(PATHS$data_proc, "gdelt_candidates.rds")
rss_f   <- file.path(PATHS$data_proc, "rss_items.rds")
if (file.exists(gdelt_f)) {
  g <- readRDS(gdelt_f)
  mentions <- rbind(mentions, data.frame(
    text      = paste(g$title, g$domain %||% "", sep = " | "),
    url       = as.character(g$url),
    date      = substr(as.character(g$seendate), 1, 8),
    publisher = "GDELT",
    stringsAsFactors = FALSE))
}
if (file.exists(rss_f)) {
  r <- readRDS(rss_f)
  # совместимость имён колонок: description (02-экспорт) / desc (старый формат)
  desc_col <- if ("description" %in% names(r)) r$description else r$desc
  mentions <- rbind(mentions, data.frame(
    text      = paste(r$title, desc_col, sep = ". "),
    url       = as.character(r$link),
    date      = as.character(r$pub_date),
    publisher = as.character(r$publisher),
    stringsAsFactors = FALSE))
}
log_info("Входных упоминаний: ", nrow(mentions))
if (!nrow(mentions)) { log_info("Корпус пуст — сбор не дал данных. Выход."); quit(save = "no") }

## ---------- 2. Нормализация -------------------------------------------------
mentions$text_norm <- str_to_lower(str_squish(enc2utf8(mentions$text)))

## ---------- 3. Словари NER / классификаторов -------------------------------
# Названия систем/КА, часто встречающиеся в открытых отчётах (справочник,
# а НЕ утверждение об инцидентах — совпадение лишь помечает текст)
SAT_LEXICON <- c("viasat", "ka-sat", "starlink", "oneweb", "inmarsat", "iridium",
                 "gps", "galileo", "glonass", "beidou", "sentinel", "landsat",
                 "goes", "moscow", "express-amaru", "yamoy", "sedu", "ses",
                 "eutelsat", "intelsat", "telesat", "orbcomm", "globalstar",
                 "ics", "hx", "skikua", "kymeta", "satcom", "tt&c", "ground station",
                 "cube sat", "cubesat", "nanosat", "earth observation", "nilesat")

VECTOR_PATTERNS <- list(          # паттерн -> код dict_vector
  jam            = c("\\bjam(m)?ing\\b", "\\binterference.*(signal|broadcast|gps)",
                     "заглуш", "electronic warfare", "ew station"),
  spoof          = c("\\bspoof\\w*\\b", "meaconing", "gnss.*fake", "false gps"),
  intercept      = c("intercept(ed|ion)?.*(telemetry|signal|transmission)",
                     "\\beavesdrop\\w*\\b"),
  uplink_hijack  = c("unauthorized (uplink|transmission)", "hijack.*(satellite|command)",
                     "transmit.*without authoriz"),
  malware        = c("\\bmalware\\b", "wiper", "\\bvirus\\b", "acid rain", "hermeticwizard",
                     "kazuar", "\\btrojan\\b", "ransomware"),
  exploit_cve    = c("\\bcve-\\d{4}-\\d{4,7}\\b", "exploit\\w*.*vulnerabilit",
                     "zero-day", "vulnerabilit\\w*.*exploit"),
  credential     = c("credential", "account.*compromis", "phishing.*access"),
  supply_chain   = c("supply chain", "backdoor.*(vendor|firmware)",
                     "compromised.*(update|firmware|software)", "solarwinds-style"),
  ddos           = c("\\bddos\\b", "denial[- ]of[- ]service"),
  insider        = c("insider", "\\brestricted access\\b.*leak"),
  phishing       = c("\\bphish\\w*\\b", "spear.?phish"),
  breach_disc    = c("data (breach|leak)", "exfiltrat\\w*", "stolen.*(data|imagery)")
)

CVE_RE  <- regex("(?i)cve-\\d{4}-\\d{4,7}")
DATE_RE <- regex("(?i)(january|february|march|april|may|june|july|august|september|october|november|december)[ ,]+\\d{1,2},? \\d{4}|\\d{4}-\\d{2}-\\d{2}")

## ---------- 4. Разметка -----------------------------------------------------
tag_one <- function(txt) {
  vec_hits <- sapply(names(VECTOR_PATTERNS), function(k)
    any(str_detect(txt, VECTOR_PATTERNS[[k]])))
  list(vectors    = paste(names(vec_hits)[vec_hits], collapse = ";"),
       n_vectors  = sum(vec_hits),
       satellites = paste(unique(unlist(lapply(SAT_LEXICON, function(s)
                       if (str_detect(txt, fixed(s))) s))), collapse = ";"),
       cves       = paste(unique(str_extract_all(txt, CVE_RE)[[1]]), collapse = ";"),
       dates      = paste(unique(str_extract_all(txt, DATE_RE)[[1]]), collapse = ";"),
       space_ctx  = any(str_detect(txt, c("satellite", "spacecraft", "orbit", "ground station",
                                          "gnss", "\\bgps\\b", "uplink", "downlink", "transponder",
                                          "vsat", "tt&c", "cubesat", "launch")),
                        .dims = FALSE) || length(unlist(regmatches(txt, gregexpr("satellite|orbit|gnss|vsat", txt)))) > 0,
       cyber_ctx  = any(str_detect(txt, c("hack", "cyber", "attack", "breach", "malware",
                                          "vulnerabilit", "jam", "spoof", "intrusion",
                                          "phish", "ddos", "exploit", "compromis"))))
}
tags <- lapply(mentions$text_norm, tag_one)
mentions$vectors        <- sapply(tags, `[[`, "vectors")
mentions$satellites    <- sapply(tags, `[[`, "satellites")
mentions$cves          <- sapply(tags, `[[`, "cves")
mentions$dates_found   <- sapply(tags, `[[`, "dates")
mentions$is_incident_candidate <-
  sapply(tags, `[[`, "space_ctx") & sapply(tags, `[[`, "cyber_ctx") &
  sapply(tags, `[[`, "n_vectors") >= 1

## ---------- 5. Дедупликация и маппинг векторов на коды --------------------
mentions$dup_key <- str_to_lower(str_replace_all(mentions$text, "[^a-z0-9 ]", ""))
mentions <- mentions[!duplicated(mentions$dup_key), ]

CODE_MAP <- c(jam="V-JAM", spoof="V-SPF", intercept="V-INT", uplink_hijack="V-UPL",
              malware="V-MAL", exploit_cve="V-EXP", credential="V-CRED",
              supply_chain="V-SUP", ddos="V-DOS", insider="V-INS",
              phishing="V-PHISH", breach_disc="V-UNAUTH-DISC")
map_codes <- function(s) {
  if (!length(s) || is.na(s) || !nzchar(s)) return("")
  k <- strsplit(s, ";")[[1]]; k <- k[nzchar(k)]
  paste(CODE_MAP[k], collapse = ";")
}
mentions$vector_codes <- vapply(mentions$vectors, map_codes, character(1))

out <- file.path(PATHS$data_proc, "corpus_tagged.csv")
write.csv(mentions[, c("text","url","date","publisher","vector_codes",
                       "satellites","cves","dates_found","is_incident_candidate")],
          out, row.names = FALSE, fileEncoding = "UTF-8")

log_info("Упоминаний после дедупликации: ", nrow(mentions))
log_info("Кандидатов «инцидент ИБ в космосе»: ", sum(mentions$is_incident_candidate))
log_info("Результат: ", out, "  (ожидают ручной верификации C1–C4 перед загрузкой в БД)")
