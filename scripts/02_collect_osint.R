#!/usr/bin/env Rscript
# ============================================================================
# 02_collect_osint.R — ЭТАП 2: сбор OSINT-корпуса об инцидентах ИБ в космосе
#                    (ИСПРАВЛЕННАЯ ВЕРСИЯ: обход антибот-страниц, макс. охват)
# ----------------------------------------------------------------------------
# ПРОБЛЕМА (старая версия): сайты отдавали вместо данных «антибот»-страницы:
#   * Akamai "Access Denied"        (CISA)
#   * Cloudflare "Just a moment..." (BleepingComputer и др.)
#   * GDELT HTTP 429 rate-limit     (текст вместо JSON)
#   * WordPress-фиды с блокировкой нестандартного User-Agent
#
# РЕШЕНИЕ (многоуровневый anti-bot evasion, без имитации личности):
#   1. Браузерный стек заголовков (User-Agent Chrome + Accept-Language +
#      Sec-Fetch-* + Upgrade-Insecure-Requests) — многие WAF пропускают
#      запросы только с полным «человеческим» набором заголовков.
#   2. Детектирование антибот-контента по сигнатурам (не сохранять мусор!).
#   3. Автоматический повтор с экспоненциальной backoff при 429/503.
#   4. Для GDELT — соблюдение правила >=6 сек между запросами + доп. пауза
#      и повтор при rate-limit; валидация JSON перед парсингом.
#   5. FALLBACK-ЦЕПОЧКА через открытые read-прокси (allorigins.win,
#      codetabs proxy, corsproxy.io) — они стоят «на стороне клиента» и
#      обычно не блокируются WAF целевого сайта.
#   6. Вежливые джиттер-паузы между фидными запросами (anti-throttle).
#   7. Кэширование всех СЫРЫХ снимков (только валидных!) в data/raw/<src>/ —
#      повторный рендер воспроизводит корпус один в один (offline-режим).
#
# ИСТОЧНИКИ:
#   1. RSS   — космические + кибер + OT/ICS фиды (расширенный пул)
#   2. GDELT DOC 2.0 — событийные паттерны (кандидаты, low reliability)
#   3. CISA  — RSS advisories/ICS + KEV catalog (JSON)
#   4. NASA  — RSS пресс-релизов/блогов + ESA news RSS
#
# ЕДИНАЯ СХЕМА ДАТАСЕТА (data/processed/corpus_raw.rds / .csv):
#   source, source_feed, category, title, url, pub_date (chr ISO),
#   event_date (chr, обычно NA), description, snapshot_date (Date)
#
# Запуск:  Rscript scripts/02_collect_osint.R [--offline] [--retries=N]
# ============================================================================

this_file <- sub("^--file=", "", grep("^--file=", commandArgs(FALSE), value = TRUE)[1])
if (is.na(this_file) || !nzchar(this_file)) this_file <- "scripts/02_collect_osint.R"
source(file.path(dirname(this_file), "00_config.R"))

OFFLINE <- "--offline" %in% commandArgs(trailingOnly = TRUE)
POLITE  <- !OFFLINE   # в offline-режиме сетевые паузы не нужны
args    <- commandArgs(trailingOnly = TRUE)
MAX_RETRIES <- as.integer(gsub("^--retries=", "", grep("^--retries=", args, value = TRUE)[1]))
if (is.na(MAX_RETRIES)) MAX_RETRIES <- 3L

suppressPackageStartupMessages({
  library(httr)
  library(xml2)
  library(jsonlite)
  library(curl)   # curl_escape для URL-кодирования
})

set.seed(42)  # детерминированный джиттер пауз -> воспроизводимость таймингов

# Дата среза: фиксирована в 00_config.R (DATA_CUTOFF_DATE) — воспроизводимость.
# Можно переопределить флагом --snapshot=YYYY-MM-DD для нового планового среза.
SNAPSHOT_DATE <- as.Date(DATA_CUTOFF_DATE)
.snap_arg <- grep("^--snapshot=", args, value = TRUE)[1]
if (!is.na(.snap_arg)) SNAPSHOT_DATE <- as.Date(sub("^--snapshot=", "", .snap_arg))
SNAPSHOT_TS   <- format(Sys.time(), "%Y%m%d_%H%M%S")
RAW_DIR       <- PATHS$data_raw
dir.create(RAW_DIR, recursive = TRUE, showWarnings = FALSE)
invisible(lapply(c("rss", "gdelt", "cisa", "nasa", "meta"),
                 function(d) dir.create(file.path(RAW_DIR, d), showWarnings = FALSE)))
dir.create(PATHS$data_proc, recursive = TRUE, showWarnings = FALSE)

`%||%` <- function(a, b) if (is.null(a)) b else a

# ----------------------------------------------------------------------------
# 0. КОНФИГУРАЦИЯ ИСТОЧНИКОВ
# ----------------------------------------------------------------------------

# Браузерный стек заголовков — ключевой фикс против WAF/Akamai/Cloudflare
BROWSER_HEADERS <- c(
  "User-Agent" = paste0("Mozilla/5.0 (Windows NT 10.0; Win64; x64) ",
                        "AppleWebKit/537.36 (KHTML, like Gecko) ",
                        "Chrome/124.0.0.0 Safari/537.36"),
  "Accept"     = "application/rss+xml,application/atom+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language" = "en-US,en;q=0.9",
  "Cache-Control"   = "no-cache",
  "Upgrade-Insecure-Requests" = "1",
  "Sec-Fetch-Dest"  = "document",
  "Sec-Fetch-Mode"  = "navigate",
  "Sec-Fetch-Site"  = "none"
)

# Расширенный пул RSS-фидов (space + cyber + ICS)
RSS_FEEDS <- data.frame(
  source_feed = c(
    # --- космические ---
    "SpaceNews", "SpaceflightNow", "SpaceSafetyMagazine",
    "ParabolicArc", "SpaceWatchGlobal", "ArsTechnica_Space",
    "NASASpaceflight", "PayloadSpace", "TheRegister_Science",
    # --- кибербезопасность ---
    "TheHackersNews", "DarkReading", "SecurityWeek",
    "KrebsOnSecurity", "TheRecord", "BleepingComputer",
    # --- OT/ICS ---
    "ControlGlobal"
  ),
  url = c(
    "https://spacenews.com/feed/",
    "https://spaceflightnow.com/feed/",
    "https://www.spacesafetymagazine.com/feed/",
    "https://parabolicarc.com/feed/",
    "https://spacewatch.global/feed/",
    "https://arstechnica.com/space/feed/",
    "https://www.nasaspaceflight.com/feed/",
    "https://payloadspace.com/feed/",
    "https://www.theregister.com/headlines.atom",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.darkreading.com/rss.xml",
    "https://www.securityweek.com/feed/",
    "https://krebsonsecurity.com/feed/",
    "https://therecord.media/feed",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.controlglobal.com/rss"
  ),
  category = c(rep("space", 9), rep("cyber", 6), "ics"),
  stringsAsFactors = FALSE
)

# GDELT — событийные паттерны (только кандидаты; low reliability)
SPACE_CYBER_PATTERNS <- c(
  "satellite hack", "satellite cyberattack", "satellite jamming",
  "satellite spoofing", "GNSS spoofing", "GPS jamming attack",
  "ground station cyber", "space cyber incident",
  "satellite telemetry intercepted", "Starlink jamming",
  "Viasat hack", "Ka-SAT attack"
)

# Post-фильтры релевантности для официальных источников
CISA_KW <- paste("satellite|space|ics|scada|gps|gnss|aerospace|vsat|telecom",
                 "launch|lockheed|boeing|spacex|northrop|raytheon|l3harris",
                 "sonik|satsuite|starlink|viasat|oneweb|kuiper", sep = "|")
NASA_KW <- paste("cyber|hack|breach|vulnerab|intrusion|security incident",
                 "satellite|iss|artemis|jwst|hubble|orion|launch|mission",
                 "ground station|telemetry|command", sep = "|")

log_step <- function(step, msg) log_info(sprintf("[%s] %s", step, msg))

# ----------------------------------------------------------------------------
# 1. АНТИБОТ-ДЕТЕКТОР + УНИВЕРСАЛЬНЫЙ ЗАГРУЗЧИК С FALLBACK-ЦЕПОЧКОЙ
# ----------------------------------------------------------------------------

# Сигнатуры антибот-страниц: если ответ их содержит — данные НЕ получены.
# ВАЖНО: проверка выполняется ТОЛЬКО по «шапке» документа (первые 4 КБ) —
# новостные RSS legitimately содержат фразы вроде "Access Denied" в текстах
# статей, и проверка по всему телю давала бы ложные срабатывания.
is_antibot_page <- function(txt) {
  if (is.null(txt) || !nzchar(txt)) return(TRUE)
  head_txt <- substr(gsub("[\r\n]", " ", txt), 1, 4000)
  sigs <- c(
    "Just a moment",                       # Cloudflare challenge
    "Checking your browser",               # Cloudflare
    "^\\s*<HTML.*Access Denied",           # Akamai (только в начале!)
    "Attention Required! \\| Cloudflare",  # CF block page
    "Enable JavaScript and cookies",       # JS-challenge
    "Pardon Our Interruption",             # Fastly
    "Request unsuccessful.*Incapsula",     # Imperva
    "<title>403 Forbidden",                # nginx block
    "Please limit requests to one every"   # GDELT rate-limit text
  )
  any(vapply(sigs, function(s) grepl(s, head_txt, ignore.case = TRUE), logical(1)))
}

looks_like_feed <- function(txt) {
  nzchar(txt) && grepl("<(rss|feed|rdf)[ >]", substr(txt, 1, 4000), ignore.case = TRUE)
}
looks_like_json <- function(txt) {
  nzchar(txt) && grepl("^\\s*[{\\[]", txt)
}

# Прямая загрузка через httr с браузерными заголовками
fetch_direct <- function(url, timeout_s = 25) {
  tryCatch({
    res <- httr::GET(url, httr::timeout(timeout_s),
                     do.call(httr::add_headers, as.list(BROWSER_HEADERS)))
    if (httr::status_code(res) %in% c(429L, 503L)) return(list(status = httr::status_code(res), txt = NULL))
    if (httr::http_error(res))                     return(list(status = httr::status_code(res), txt = NULL))
    txt <- httr::content(res, "text", encoding = "UTF-8")
    list(status = httr::status_code(res), txt = txt)
  }, error = function(e) list(status = -1L, txt = NULL))
}

# Извлечение «полезного» тела из ответа reader-прокси (r.jina.ai отдаёт
# markdown с преамбулой "Title:/URL Source:/Markdown Content:")
strip_reader_preamble <- function(txt) {
  if (is.null(txt)) return(NULL)
  m <- regmatches(txt, regexpr("Markdown Content:\\s*", txt))
  if (length(m) == 1) txt <- sub("^.*Markdown Content:\\s*", "", txt, perl = TRUE)
  txt
}

# Fallback-цепочка reader-прокси. r.jina.ai — основной обход Cloudflare/Akamai:
# его краулер рендерит страницу как браузер и отдаёт контент; для XML/JSON
# фидов содержимое сохраняется в теле "Markdown Content".
PROXY_BUILDERS <- list(
  jina       = function(u) sprintf("https://r.jina.ai/%s", u),
  jina_text  = function(u) sprintf("https://r.jina.ai/%s", u),  # тот же, но ок="any"
  allorigins = function(u) sprintf("https://api.allorigins.win/raw?url=%s", curl::curl_escape(u)),
  codetabs   = function(u) sprintf("https://api.codetabs.com/v1/proxy?quest=%s", curl::curl_escape(u))
)
fetch_via_proxy <- function(url, expect = "feed") {
  for (nm in names(PROXY_BUILDERS)) {
    if (nm == "jina_text") next
    r <- fetch_direct(PROXY_BUILDERS[[nm]](url), timeout_s = 60)
    body <- strip_reader_preamble(r$txt %||% "")
    if (!is.character(body)) body <- ""
    good <- switch(expect,
      feed = looks_like_feed(body) ||
             grepl("^#{2,4}\\s*\\[.+?\\]\\(https?://", body),
      json = looks_like_json(body) || grepl('"cveID"|"articles"', body),
      any  = nzchar(body) && !is_antibot_page(body))
    if (isTRUE(good)) return(list(txt = body, via = nm))
    if (POLITE) Sys.sleep(runif(1, 1, 2))
  }
  list(txt = NULL, via = NA_character_)
}

# Парсинг markdown-списка ссылок (ответ r.jina.ai для заблокированных RSS):
# формат "### [Заголовок](URL)" + опц. строки текста/даты после
parse_markdown_links <- function(txt, default_date = NA_character_) {
  lines <- unlist(strsplit(txt, "\n", fixed = TRUE))
  idx   <- grep("^#{2,4}\\s*\\[(.+?)\\]\\((https?://[^)]+)\\)", lines)
  if (!length(idx)) return(NULL)
  mk <- regmatches(lines[idx],
        regexec("^#{2,4}\\s*\\[(.+?)\\]\\((https?://[^)]+)\\)", lines[idx]))
  titles <- vapply(mk, function(m) if (length(m) == 3) m[2] else NA_character_, character(1))
  links  <- vapply(mk, function(m) if (length(m) == 3) m[3] else NA_character_, character(1))
  # описание = следующая непустая строка после заголовка (до следующего ###)
  desc <- vapply(seq_along(idx), function(k) {
    s <- idx[k] + seq_len(min(6, length(lines) - idx[k]))
    cand <- trimws(lines[s])
    cand <- cand[nzchar(cand) & !grepl("^#{2,4}\\s*\\[", cand)]
    substr(gsub("[*_`]", "", paste(head(cand, 2), collapse = " ")), 1, 1500)
  }, character(1))
  data.frame(title = trimws(titles), link = links, pub_date = default_date,
             description = desc, stringsAsFactors = FALSE)
}

# Универсальный загрузчик: cache -> direct (retry+backoff) -> proxy chain.
# Возвращает list(txt, via); кэширует валидный сырой снимок на диск.
smart_fetch <- function(url, cache_dir, cache_name, expect = c("feed", "json", "any")) {
  expect <- match.arg(expect)
  fpath  <- file.path(cache_dir, cache_name)

  ## 1. Кэш (гарантия воспроизводимости и offline-рендера)
  if (file.exists(fpath)) {
    txt <- paste(readLines(fpath, warn = FALSE, encoding = "UTF-8"), collapse = "\n")
    # Кэшируются ДВА формата: чистый ответ (direct/allorigins) и reader-markdown
    # от r.jina.ai ("...Markdown Content:\n<payload>"). Для markdown-кэша
    # извлекаем полезную нагрузку до проверок валидности.
    payload <- strip_reader_preamble(txt)
    good_cached <- switch(expect,
      feed = looks_like_feed(payload) ||
             grepl("^#{2,4}\\s*\\[.+?\\]\\(https?://", payload),   # markdown-фид
      json = looks_like_json(payload) || grepl('"articles"|\'articles\'|"cveID"', payload),
      any  = nzchar(payload) && !is_antibot_page(payload))
    if (isTRUE(good_cached) && !is_antibot_page(payload))
      return(list(txt = payload, via = "cache"))
  }
  if (OFFLINE) return(list(txt = NULL, via = NA_character_))

  ok <- function(txt) {
    if (is.null(txt) || is_antibot_page(txt)) return(FALSE)
    switch(expect,
           feed = looks_like_feed(txt),
           json = looks_like_json(txt),
           any  = looks_like_feed(txt) || looks_like_json(txt) ||
                  grepl("<html", txt, ignore.case = TRUE))
  }

  ## 2. Прямые попытки с экспоненциальным backoff (429/503/антибот)
  for (attempt in seq_len(MAX_RETRIES)) {
    r <- fetch_direct(url)
    if (ok(r$txt)) {
      writeLines(r$txt, fpath, useBytes = TRUE)
      return(list(txt = r$txt, via = "direct"))
    }
    wait <- min(60, round((2 ^ attempt) * runif(1, 0.8, 1.6)))  # джиттер (seed=42)
    log_step("FETCH", sprintf("попытка %d/%d не удалась (HTTP %s) → пауза %ss: %s",
                              attempt, MAX_RETRIES, r$status, wait, url))
    if (POLITE) Sys.sleep(wait)
  }

  ## 3. Fallback-цепочка reader-прокси (r.jina.ai и др.)
  p <- fetch_via_proxy(url, expect = expect)
  if (!is.null(p$txt)) {
    writeLines(p$txt, fpath, useBytes = TRUE)
    log_step("FETCH", sprintf("получено через fallback-прокси '%s': %s", p$via, url))
    return(list(txt = p$txt, via = paste0("proxy:", p$via)))
  }
  log_step("FETCH", sprintf("ВСЕ МЕТОДЫ ИСЧЕРПАНЫ (антибот): %s", url))
  list(txt = NULL, via = NA_character_)
}

# ----------------------------------------------------------------------------
# 2. ПАРСИНГ RSS (собственный парсер xml2 — независим от версии tidyRSS)
# ----------------------------------------------------------------------------

parse_feed_xml <- function(txt) {
  x <- tryCatch(xml2::read_xml(txt, encoding = "UTF-8"), error = function(e) NULL)
  if (is.null(x)) return(NULL)
  grab <- function(nodes, path) {
    vapply(nodes, function(n) {
      f <- xml2::xml_find_first(n, paste0(".", path))
      if (inherits(f, "xml_missing")) NA_character_ else trimws(xml2::xml_text(f))
    }, character(1))
  }
  items <- xml2::xml_find_all(x, "//item | //entry")   # RSS 2.0 + Atom
  if (!length(items)) return(NULL)
  get_first <- function(n, paths) {
    for (p in paths) {
      f <- xml2::xml_find_first(n, p)
      if (!inherits(f, "xml_missing")) return(f)
    }
    NULL
  }
  out <- data.frame(
    title = grab(items, "title"),
    link = vapply(items, function(n) {
      l <- xml2::xml_find_first(n, "./link")
      href <- xml2::xml_attr(l, "href")                       # Atom <link href=...>
      val  <- if (!is.na(href) && nzchar(href)) href else
              tryCatch(trimws(xml2::xml_text(l)), error = function(e) NA_character_)
      ifelse(is.na(val) || !nzchar(val), NA_character_, val)
    }, character(1)),
    pub_date = vapply(items, function(n) {
      f <- get_first(n, c("./pubDate", "./published", "./updated", "./dc:date"))
      if (is.null(f)) NA_character_ else trimws(xml2::xml_text(f))
    }, character(1)),
    description = vapply(items, function(n) {
      f <- get_first(n, c("./description", "./summary", "./content", "./content:encoded"))
      if (is.null(f)) NA_character_ else
        substr(gsub("<[^>]+>", " ", trimws(xml2::xml_text(f))), 1, 1500)
    }, character(1)),
    stringsAsFactors = FALSE
  )
  out[stats::complete.cases(out$title, out$link), , drop = FALSE]
}

collect_rss <- function() {
  log_step("RSS", sprintf("парсинг %d фидов (browser-headers + retry + proxy-fallback)", nrow(RSS_FEEDS)))
  rows <- list(); hit <- 0L; blocked <- 0L
  for (i in seq_len(nrow(RSS_FEEDS))) {
    fd  <- RSS_FEEDS[i, ]
    r   <- smart_fetch(fd$url, file.path(RAW_DIR, "rss"),
                       sprintf("%s.xml", gsub("[^A-Za-z0-9]", "_", fd$source_feed)),
                       expect = "feed")
    it  <- NULL
    if (!is.null(r$txt)) {
      it <- parse_feed_xml(r$txt)                                  # XML-фид
      if (is.null(it) || !nrow(it)) it <- parse_markdown_links(r$txt)  # markdown от r.jina.ai
    }
    # Offline-фолбэк: smart_fetch строг к формату; пробуем распарсить кэш как есть
    if ((is.null(it) || !nrow(it)) && OFFLINE) {
      cf <- file.path(RAW_DIR, "rss", sprintf("%s.xml", gsub("[^A-Za-z0-9]", "_", fd$source_feed)))
      if (file.exists(cf)) {
        payload <- strip_reader_preamble(paste(readLines(cf, warn = FALSE, encoding = "UTF-8"), collapse = "\n"))
        it <- parse_feed_xml(payload)
        if (is.null(it) || !nrow(it)) it <- parse_markdown_links(payload)
        if (!is.null(it) && nrow(it)) r <- list(txt = payload, via = "cache-loose")
      }
    }
    if (is.null(it) || !nrow(it)) { blocked <- blocked + 1L
      log_step("RSS", sprintf("x  %-22s — нет валидного XML (антибот/ошибка)", fd$source_feed)); next }
    hit <- hit + 1L
    log_step("RSS", sprintf("OK %-22s %4d шт. (%s)", fd$source_feed, nrow(it), r$via))
    rows[[fd$source_feed]] <- transform(it,
      source = "RSS", source_feed = fd$source_feed, category = fd$category,
      event_date = NA_character_, snapshot_date = SNAPSHOT_DATE)
    if (POLITE) Sys.sleep(runif(1, 1.5, 4))   # вежливая пауза с джиттером
  }
  log_step("RSS", sprintf("успех %d / %d, заблокировано %d", hit, nrow(RSS_FEEDS), blocked))
  if (length(rows)) do.call(rbind, rows) else NULL
}

# Разбор ответа GDELT: чистый JSON | application/javascript+json ({...}) |
# reader-markdown с JSON внутри. Возвращает data.frame articles или NULL.
parse_gdelt_payload <- function(txt) {
  if (is.null(txt) || !nzchar(txt)) return(NULL)
  body <- strip_reader_preamble(txt)
  from_json_str <- function(z) tryCatch(
    jsonlite::fromJSON(z, simplifyDataFrame = TRUE)$articles, error = function(e) NULL)
  a <- from_json_str(body)                                    # вариант 1: чистый JSON
  if (is.null(a) || !length(a)) {                             # вариант 2: {...} внутри текста
    m <- regexpr("\\{.*\\}", body, perl = TRUE)
    if (m > 0) a <- from_json_str(substr(body, m[1], m[1] + attr(m, "used") - 1))
  }
  if (!is.null(a) && length(a)) return(a)
  NULL
}

# ----------------------------------------------------------------------------
# 3. GDELT DOC 2.0 — строгий rate-limit (>=6 c) + retry + валидация JSON
# ----------------------------------------------------------------------------

collect_gdelt <- function(max_records = 75L) {
  log_step("GDELT", sprintf("%d поисковых паттернов, темп >=6 c/запрос", length(SPACE_CYBER_PATTERNS)))
  base  <- "https://api.gdeltproject.org/api/v2/doc/doc"
  start <- format(SNAPSHOT_DATE - 365, "%Y%m%dT000000Z")
  endd  <- format(SNAPSHOT_DATE, "%Y%m%dT235959Z")
  rows  <- list()
  for (i in seq_along(SPACE_CYBER_PATTERNS)) {
    q <- SPACE_CYBER_PATTERNS[i]
    u <- sprintf("%s?query=%s&mode=ArtList&format=json&maxrecords=%d&startdate=%s&enddate=%s&sort=DateDesc",
                 base, curl::curl_escape(q), max_records, start, endd)
    got <- NULL
    for (attempt in 1:2) {
      if (POLITE) Sys.sleep(if (attempt == 1) max(1, 6 + runif(1, 0, 2)) else 35)  # окно rate-limit GDELT
      r <- smart_fetch(u, file.path(RAW_DIR, "gdelt"),
                       sprintf("gdelt_%02d_%s.json", i, gsub("[^A-Za-z0-9]", "_", q)),
                       expect = "json")
      if (!is.null(r$txt)) { got <- r$txt; break }
    }
    if (is.null(got)) { log_step("GDELT", sprintf("x  '%s' — rate-limit/недоступен", q)); next }
    a <- parse_gdelt_payload(got)
    if (is.null(a) || !length(a)) {
      # r.jina.ai мог отдать markdown со ссылками на статьи вместо JSON
      md <- parse_markdown_links(got, default_date = NA_character_)
      if (!is.null(md) && nrow(md)) {
        a <- data.frame(title = md$title, url = md$link, seendate = NA_character_,
                        domain = NA_character_, sourcecountry = NA_character_,
                        stringsAsFactors = FALSE)
      } else { log_step("GDELT", sprintf("OK '%s' — 0 статей", q)); next }
    }
    log_step("GDELT", sprintf("OK '%s' — %d статей", q, nrow(a)))
    rows[[q]] <- data.frame(
      title = a$title, url = a$url, pub_date = a$seendate,
      source = "GDELT", source_feed = q, category = "mixed",
      description = paste0("domain=", a$domain %||% NA, "; country=", a$sourcecountry %||% NA),
      event_date = NA_character_, snapshot_date = SNAPSHOT_DATE,
      stringsAsFactors = FALSE)
  }
  if (length(rows)) {
    d <- do.call(rbind, rows); d[!duplicated(d$url), , drop = FALSE]
  } else NULL
}

# ----------------------------------------------------------------------------
# 4. CISA: RSS advisories + ICS-advisories + KEV catalog (JSON)
# ----------------------------------------------------------------------------

collect_cisa <- function() {
  urls <- c(
    all = "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    ics = "https://www.cisa.gov/news-events/cybersecurity-advisories/ics.xml",
    kev = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  )
  rows <- list()
  for (nm in names(urls)) {
    r <- smart_fetch(urls[[nm]], file.path(RAW_DIR, "cisa"),
                     sprintf("cisa_%s.%s", nm, if (nm == "kev") "json" else "xml"),
                     expect = if (nm == "kev") "json" else "feed")
    if (is.null(r$txt)) { log_step("CISA", sprintf("x  %s — недоступен (антибот на всех каналах)", nm)); next }
    if (nm == "kev") {
      j <- tryCatch(jsonlite::fromJSON(r$txt), error = function(e) NULL)
      v <- j$vulnerabilities
      if (is.null(v) || !nrow(v)) { log_step("CISA", sprintf("x  %s — JSON не распарсен", nm)); next }
      sel <- v[grepl(CISA_KW, paste(v$product, v$cveID, v$shortDescription), ignore.case = TRUE), ]
      log_step("CISA", sprintf("OK KEV: %d/%d уязвимостей прошли space/ICS-фильтр (%s)",
                               nrow(sel), nrow(v), r$via))
      if (nrow(sel)) rows[[nm]] <- data.frame(
        title = sprintf("KEV %s: %s %s", sel$cveID, sel$vendorProject, sel$product),
        url   = sprintf("https://www.cisa.gov/known-exploited-vulnerabilities-catalog#cve=%s", sel$cveID),
        pub_date = sel$dateAdded, source = "CISA", source_feed = "KEV", category = "ics",
        description = substr(sel$shortDescription, 1, 1500),
        event_date = NA_character_, snapshot_date = SNAPSHOT_DATE, stringsAsFactors = FALSE)
    } else {
      it <- parse_feed_xml(r$txt)
      if (is.null(it) || !nrow(it)) it <- parse_markdown_links(r$txt)  # markdown-ответ r.jina.ai
      if (is.null(it) || !nrow(it)) { log_step("CISA", sprintf("x  %s — XML не распарсен", nm)); next }
      sel <- it[grepl(CISA_KW, paste(it$title, it$description), ignore.case = TRUE), ]
      log_step("CISA", sprintf("OK RSS %s: %d/%d записей релевантны (%s)", nm, nrow(sel), nrow(it), r$via))
      if (nrow(sel)) rows[[nm]] <- transform(sel,
        source = "CISA", source_feed = nm, category = "mixed",
        event_date = NA_character_, snapshot_date = SNAPSHOT_DATE)
    }
    if (POLITE) Sys.sleep(runif(1, 2, 5))
  }
  if (length(rows)) { d <- do.call(rbind, rows); d[!duplicated(d$url), , drop = FALSE] } else NULL
}

# ----------------------------------------------------------------------------
# 5. NASA / ESA RSS
# ----------------------------------------------------------------------------

collect_nasa <- function() {
  feeds <- c(
    NASA_releases = "https://www.nasa.gov/news-release/feed/",
    NASA_safety   = "https://blogs.nasa.gov/safety/feed/",
    NASA_station  = "https://blogs.nasa.gov/spacestation/feed/",
    ESA_news      = "https://www.esa.int/rssfeed/Our_Activities/Space_News"
  )
  rows <- list()
  for (nm in names(feeds)) {
    r <- smart_fetch(feeds[[nm]], file.path(RAW_DIR, "nasa"),
                     sprintf("%s.xml", nm), expect = "feed")
    it <- NULL
    if (!is.null(r$txt)) {
      it <- parse_feed_xml(r$txt)
      if (is.null(it) || !nrow(it)) it <- parse_markdown_links(r$txt)
    }
    if (is.null(it) || !nrow(it)) { log_step("NASA", sprintf("x  %s — нет данных", nm)); next }
    sel <- it[grepl(NASA_KW, paste(it$title, it$description), ignore.case = TRUE), ]
    log_step("NASA", sprintf("OK %s: %d всего, %d релевантны (%s)", nm, nrow(it), nrow(sel), r$via))
    if (nrow(sel)) rows[[nm]] <- transform(sel,
      source = if (grepl("ESA", nm)) "ESA" else "NASA", source_feed = nm,
      category = "space", event_date = NA_character_, snapshot_date = SNAPSHOT_DATE)
    if (POLITE) Sys.sleep(runif(1, 1.5, 3.5))
  }
  if (length(rows)) do.call(rbind, rows) else NULL
}

# ----------------------------------------------------------------------------
# 6. ГЛАВНЫЙ ПАЙПЛАЙН
# ----------------------------------------------------------------------------

main <- function() {
  log_step("PIPELINE", sprintf("срез %s; режим: %s; retries=%d",
                               SNAPSHOT_DATE, if (OFFLINE) "offline (кэш)" else "online", MAX_RETRIES))

  parts <- Filter(Negate(is.null), list(
    rss   = collect_rss(),
    gdelt = collect_gdelt(),
    cisa  = collect_cisa(),
    nasa  = collect_nasa()
  ))
  schema_cols <- c("source", "source_feed", "category", "title", "url",
                   "pub_date", "event_date", "description", "snapshot_date")
  if (!length(parts)) {
    log_step("PIPELINE", "НЕТ НИ ОДНОГО ИСТОЧНИКА — сохранён пустой корпус")
    corpus <- data.frame(matrix(character(0), ncol = length(schema_cols)))
    names(corpus) <- schema_cols
    corpus$snapshot_date <- as.Date(character(0))
  } else {
    corpus <- do.call(rbind, c(lapply(parts, function(d) d[, schema_cols, drop = FALSE]),
                               make.row.names = FALSE, stringsAsFactors = FALSE))
    rownames(corpus) <- NULL
  }

  saveRDS(corpus, file.path(PATHS$data_proc, "corpus_raw.rds"))
  write.csv(corpus, file.path(PATHS$data_proc,
            sprintf("corpus_raw_%s.csv", format(SNAPSHOT_DATE, "%Y%m%d"))),
            row.names = FALSE, fileEncoding = "UTF-8")

  # Метаданные среза (воспроизводимость: seed, версии, исходы по источникам)
  meta <- list(
    snapshot_date = as.character(SNAPSHOT_DATE),
    run_ts        = SNAPSHOT_TS,
    seed          = 42,
    taxonomy_ver  = TAXONOMY_VERSION,
    n_rows        = nrow(corpus),
    by_source     = as.list(table(corpus$source)),
    raw_cache_dir = RAW_DIR
  )
  write(jsonlite::toJSON(meta, auto_unbox = TRUE, pretty = TRUE),
        file.path(RAW_DIR, "meta", sprintf("snapshot_meta_%s.json", SNAPSHOT_TS)))

  cat("\n===== СВОДКА СБОРА =====\n")
  print(table(corpus$source, corpus$category))
  log_step("PIPELINE", sprintf("ГОТОВО: %d упоминаний -> data/processed/corpus_raw.rds", nrow(corpus)))
  invisible(corpus)
}

corpus <- main()

# ----------------------------------------------------------------------------
# 7. Экспорт плоских файлов для 03_nlp_pipeline.R (мост между сбором и NLP)
#    rss_items.rds   — все элементы фидов (до релеванс-фильтра, с издателем)
#    gdelt_candidates.rds — артефакты GDELT в формате, ожидаемом NLP-скриптом
# ----------------------------------------------------------------------------
export_for_nlp <- function() {
  ## RSS: парсим ВСЕ закешированные фиды (raw-корпус для NLP шире, чем corpus)
  rss_dir <- file.path(RAW_DIR, "rss")
  feed_map <- if (exists("RSS_FEEDS")) {
    setNames(as.list(RSS_FEEDS$source_feed), basename(RSS_FEEDS$url))
  } else NULL
  rf <- list.files(rss_dir, pattern = "\\.xml$", full.names = TRUE)
  items <- lapply(rf, function(f) {
    txt <- paste(readLines(f, warn = FALSE, encoding = "UTF-8"), collapse = "\n")
    payload <- strip_reader_preamble(txt)          # кэш может быть в reader-markdown
    it <- parse_feed_xml(payload)
    if (is.null(it) || !nrow(it)) it <- parse_markdown_links(payload)
    if (is.null(it) || !nrow(it)) return(NULL)
    nm <- sub("\\.xml$", "", basename(f))
    it$publisher <- nm
    it
  })
  items <- do.call(rbind, Filter(Negate(is.null), items))
  if (!is.null(items) && nrow(items)) {
    # Даты markdown-элементов ("Fri, 23 Oct 2026 ...") -> ISO-8601 (lubridate::parse_date_time)
    needs_fix <- !is.na(items$pub_date) & nzchar(items$pub_date) &
                 !grepl("^\\d{4}-\\d{2}|^\\d{8}T", items$pub_date)
    if (any(needs_fix)) {
      parsed <- lubridate::parse_date_time(items$pub_date[needs_fix],
                orders = c("a b d Y T H M S z", "a b d Y H M S z", "a b d Y", "Y-m-d H:M:S", "Y-m-d"),
                quiet = TRUE)
      items$pub_date[needs_fix] <- ifelse(is.na(parsed), NA_character_, format(parsed, "%Y-%m-%dT%H:%M:%SZ"))
    }
    items <- items[!duplicated(items$link %||% items$title), , drop = FALSE]
    saveRDS(items, file.path(PATHS$data_proc, "rss_items.rds"))
    log_step("EXPORT", sprintf("rss_items.rds: %d элементов фидов", nrow(items)))
  }

  ## GDELT: читаем закешированные JSON напрямую (без фильтра по ключевым словам)
  gd <- list.files(file.path(RAW_DIR, "gdelt"), pattern = "\\.json$", full.names = TRUE)
  grows <- lapply(gd, function(f) {
    txt <- paste(readLines(f, warn = FALSE, encoding = "UTF-8"), collapse = "\n")
    a <- parse_gdelt_payload(txt)
    if (is.null(a) || !length(a)) return(NULL)
    a$pattern <- sub("^gdelt_\\d+_|\\.json$", "", basename(f))
    a
  })
  grows <- do.call(rbind, Filter(Negate(is.null), grows))
  if (!is.null(grows) && nrow(grows)) {
    grows <- grows[!duplicated(grows$url), , drop = FALSE]
    saveRDS(grows, file.path(PATHS$data_proc, "gdelt_candidates.rds"))
    log_step("EXPORT", sprintf("gdelt_candidates.rds: %d статей GDELT", nrow(grows)))
  }
}
export_for_nlp()
