#!/usr/bin/env Rscript
# ============================================================
# 00_config.R — единая конфигурация проекта (импортируется всеми скриптами)
# Воспроизводимость: детерминированные пути, seed, версия таксономии, дата среза.
# ============================================================

## --- Идентификация проекта и параметры воспроизводимости ------------------
PROJECT_NAME        <- "space-ib-incidents"
TAXONOMY_VERSION    <- "1.0.0"     # должна совпадать с taxonomy/taxonomy_versions.csv
DATA_CUTOFF_DATE    <- "2026-10-24" # дата среза OSINT-корпуса (фиксирована!)
NLP_PIPELINE_VER    <- "0.1.0"
set.seed(42)                        # глобальный детерминированный seed

## --- Пути ------------------------------------------------------------------
ROOT      <- tryCatch(dirname(sys.frame(1)$ofile), error = function(e) getwd())
if (is.null(ROOT) || !nzchar(ROOT)) ROOT <- getwd()
# Если скрипт запущен из scripts/, поднимаемся к корню проекта
if (basename(ROOT) == "scripts") ROOT <- dirname(ROOT)

PATHS <- list(
  taxonomy   = file.path(ROOT, "taxonomy"),
  data_raw   = file.path(ROOT, "data", "raw"),
  data_proc  = file.path(ROOT, "data", "processed"),
  db         = file.path(ROOT, "db"),
  analysis   = file.path(ROOT, "analysis"),
  report     = file.path(ROOT, "report")
)

DB_FILE <- file.path(PATHS$db, "incidents.sqlite")

## --- Проверка окружения -----------------------------------------------------
need_libs <- c("DBI", "RSQLite")
missing   <- setdiff(need_libs, rownames(installed.packages()))
if (length(missing)) {
  stop(sprintf("Установите недостающие пакеты: %s", paste(missing, collapse = ", ")))
}

## --- Утилита логирования ----------------------------------------------------
log_info <- function(...) {
  cat(sprintf("[%s] %s\n", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), paste0(...)))
}

## --- Чтение версионируемой таксономии (CSV — единственный источник истины) --
read_taxonomy <- function() {
  lapply(list.files(PATHS$taxonomy, pattern = "\\.csv$", full.names = TRUE),
         function(f) read.csv(f, stringsAsFactors = FALSE, encoding = "UTF-8")) |>
    stats::setNames(tools::file_path_sans_ext(basename(list.files(PATHS$taxonomy,
                                                                  pattern = "\\.csv$"))))
}
