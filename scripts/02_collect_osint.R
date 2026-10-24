#!/usr/bin/env Rscript
# ============================================================
# 02_collect_osint.R — ЭТАП 2: сбор OSINT-корпуса из открытых источников
#
# Источники (см. data/raw/sources_catalog.psv):
#   - RSS лент (SpaceNews и др.)            — xml2/rvest
#   - CISA Cybersecurity Advisories index   — rvest (scrape списка)
#   - GDELT DOC 2.0 API                     — httr (JSON), событийные запросы
#   - MITRE ATLAS STIX bundle               — httr+jsonlite (для словаря техник)
#
# ПРИНЦИПЫ:
#   * Каждый снимок сохраняется в data/raw/<source>/snapshot_<cutoff>.<ext>
#     => повторный запуск при отсутствии сети работает с кэшем (воспроизводимость!).
#   * Никаких выдуманных данных: парсер извлекает ТОЛЬКО то, что реально скачал.
#   * set.seed(42); все сетевые таймауты ограничены.
#
# Запуск: Rscript scripts/02_collect_osint.R [--offline]
# ============================================================

this_file <- sub("^--file=", "", grep("^--file=", commandArgs(FALSE), value = TRUE)[1])
if (is.na(this_file) || !nzchar(this_file)) this_file <- "scripts/02_collect_osint.R"
source(file.path(dirname(this_file), "00_config.R"))

OFFLINE <- "--offline" %in% commandArgs(trailingOnly = TRUE)

## --- Необязательные зависимости: деградация graceful ------------------------
has_pkg <- function(p) requireNamespace(p, quietly = TRUE)
need    <- c("xml2", "rvest", "httr", "jsonlite")
missing <- need[!vapply(need, has_pkg, logical(1))]
if (length(missing) && !OFFLINE) {
  log_info("Устанавливаю пакеты: ", paste(missing, collapse = ", "))
  install.packages(missing, repos = "https://cloud.r-project.org", quiet = TRUE)
}
USE_NET <- !OFFLINE && all(vapply(need, has_pkg, logical(1)))
if (!USE_NET) log_info("Режим без сети: работаем только по локальному кэшу data/raw/")

save_snapshot <- function(dir_, fname, content) {
  dir.create(dir_, recursive = TRUE, showWarnings = FALSE)
  writeLines(content, file.path(dir_, fname), useBytes = TRUE)
  log_info("Сохранён снимок: ", file.path(dir_, fname))
}

cutoff_tag <- gsub("-", "", DATA_CUTOFF_DATE)

## ---------------------------------------------------------------------------
## 1. RSS-ленты (SpaceNews и пр. из каталога со status=active и source_type=news)
## ---------------------------------------------------------------------------
## Каталог источников: пропускаем комментарии '#', разделитель '|'
read_catalog <- function(f) {
  lines <- readLines(f, warn = FALSE)
  lines <- lines[!grepl("^\\s*#", lines) & nzchar(trimws(lines))]
  txt <- paste(lines, collapse = "\n")
  df <- read.delim(text = txt, sep = "|", stringsAsFactors = FALSE, quote = "")
  # нормализуем имена (первая строка — заголовок)
  names(df) <- gsub("^\\s+|\\s+$", "", names(df))
  df
}
catalog <- read_catalog(file.path(PATHS$data_raw, "sources_catalog.psv"))

fetch_rss <- function(url, outdir) {
  f <- file.path(outdir, sprintf("snapshot_%s.xml", cutoff_tag))
  if (file.exists(f)) { log_info("Кэш RSS: ", f); return(tryCatch(xml2::read_xml(f), error = function(e) NULL)) }
  if (!USE_NET) return(NULL)
  txt <- tryCatch(httr::content(httr::GET(url, httr::timeout(20),
                                          httr::add_headers("User-Agent" = "Mozilla/5.0 (research pipeline)")),
                                "text", encoding = "UTF-8"),
                  error = function(e) NULL)
  # Валидация: антибот-страницы / пустые ответы не сохраняем как данные
  if (is.null(txt) || !grepl("<(rss|feed|rdf)", txt, ignore.case = TRUE)) {
    log_info("RSS: валидный XML не получен (антибот-фильтр или ошибка): ", url); return(NULL)
  }
  save_snapshot(outdir, basename(f), txt)
  xml2::read_xml(f)
}

rss_items <- do.call(rbind, lapply(seq_len(nrow(catalog)), function(i) {
  s <- catalog[i, ]
  if (s$status != "active" || s$source_type != "news") return(NULL)
  x <- fetch_rss(s$url_pattern, file.path(PATHS$data_raw, s$publisher))
  if (is.null(x)) { log_info("Нет данных RSS: ", s$publisher); return(NULL) }
  items <- rvest::xml_find_all(x, "//item")
  d <- data.frame(
    title    = vapply(items, function(n) tryCatch(rvest::xml_text(rvest::xml_find_first(n, ".//title")),  error = function(e) NA_character_), character(1)),
    link     = vapply(items, function(n) tryCatch(rvest::xml_text(rvest::xml_find_first(n, ".//link")),   error = function(e) NA_character_), character(1)),
    pub_date = vapply(items, function(n) tryCatch(rvest::xml_text(rvest::xml_find_first(n, ".//pubDate")), error = function(e) NA_character_), character(1)),
    desc     = vapply(items, function(n) tryCatch(rvest::xml_text(rvest::xml_find_first(n, ".//description")), error = function(e) NA_character_), character(1)),
    stringsAsFactors = FALSE
  )
  transform(d, publisher = s$publisher, source_id = s$source_id)
}))
if (!is.null(rss_items) && nrow(rss_items)) {
  saveRDS(rss_items, file.path(PATHS$data_proc, "rss_items.rds"))
  log_info("RSS-упоминаний собрано: ", nrow(rss_items))
} else log_info("RSS-упоминаний: 0 (нет сети или лента не отдаёт данные)")

## ---------------------------------------------------------------------------
## 2. CISA Advisories — индексная страница (список advisory с датами)
## ---------------------------------------------------------------------------
fetch_cisa_index <- function() {
  outdir <- file.path(PATHS$data_raw, "CISA"); f <- file.path(outdir, sprintf("advisories_%s.html", cutoff_tag))
  if (file.exists(f)) { log_info("Кэш CISA: ", f); return(rvest::read_html(f)) }
  if (!USE_NET) return(NULL)
  res <- tryCatch(httr::GET("https://www.cisa.gov/news-events/cybersecurity-advisories",
                            httr::timeout(25)), error = function(e) NULL)
  if (is.null(res) || httr::http_error(res)) return(NULL)
  save_snapshot(outdir, basename(f), httr::content(res, "text", encoding = "UTF-8"))
  rvest::read_html(f)
}
page <- fetch_cisa_index()
if (!is.null(page)) {
  links <- rvest::html_elements(page, "a[href*='/current-activity']") |>
    rvest::html_attr("href") |> unique()
  log_info("CISA: найдено ссылок на материалы: ", length(links))
  writeLines(links, file.path(PATHS$data_proc, "cisa_advisory_links.txt"))
} else log_info("CISA: данные недоступны в этом окружении (запись в корпус пропущена)")

## ---------------------------------------------------------------------------
## 3. GDELT DOC 2.0 API — событийные запросы (только кандидаты; low reliability)
## ---------------------------------------------------------------------------
GDELT_QUERIES <- c("satellite jamming", "GPS spoofing", "satellite cyberattack",
                  "ground station hack", "satellite telemetry intercepted")
gdelt_fetch <- function(q) {
  if (!USE_NET) return(NULL)
  url <- sprintf("https://api.gdeltproject.org/api/v2/doc/doc?query=%s&mode=artlist&maxrecords=50&format=json",
                 curl::curl_escape(q))
  res <- tryCatch(httr::GET(url, httr::timeout(25),
                            httr::add_headers("User-Agent" = "research-pipeline/0.1")),
                  error = function(e) NULL)
  if (is.null(res) || httr::http_error(res)) return(NULL)
  txt <- httr::content(res, "text", encoding = "UTF-8")
  # GDELT отдаёт rate-limit-текст вместо JSON — детектируем и пропускаем
  if (!nzchar(txt) || !grepl("^\\s*\\{", txt)) {
    log_info("GDELT: ответ не-JSON (rate limit) для запроса: ", q); return(NULL)
  }
  j <- jsonlite::fromJSON(txt, simplifyDataFrame = TRUE)
  a <- j$articles
  if (is.null(a) || !nrow(a)) return(NULL)
  transform(a[, c("url","title","seendate","domain","sourcecountry")], query = q)
}
g <- do.call(rbind, Filter(Negate(is.null), lapply(GDELT_QUERIES, function(q) {
  Sys.sleep(6)  # вежливый темп: GDELT требует >=1 запрос / 5 сек
  gdelt_fetch(q)
})))
if (!is.null(g) && nrow(g)) {
  saveRDS(g, file.path(PATHS$data_proc, "gdelt_candidates.rds"))
  log_info("GDELT кандидатов: ", nrow(g))
} else log_info("GDELT: кандидатов 0 (сеть недоступна или пустой ответ)")

log_info("Этап сбора завершён. Срез данных: ", DATA_CUTOFF_DATE)
