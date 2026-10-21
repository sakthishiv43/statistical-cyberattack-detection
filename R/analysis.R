# Statistical Detection of Cyberattacks Using Network Traffic Data
# Student: Sakthi Shivram M | RegNo: 24BYB1168
# Base R only. Place CIC-IDS2017 CSV file(s) in ./data before running.

set.seed(1168)

project_root <- getwd()
data_dir <- file.path(project_root, "data")
results_dir <- file.path(project_root, "results")
plots_dir <- file.path(project_root, "plots")
dir.create(results_dir, showWarnings = FALSE, recursive = TRUE)
dir.create(plots_dir, showWarnings = FALSE, recursive = TRUE)

# Read CSV files. Large files can be sampled after reading to reduce analysis time.
csv_files <- list.files(data_dir, pattern = "\\.csv$", full.names = TRUE,
                        ignore.case = TRUE)
if (length(csv_files) == 0) {
  stop("No CSV files found in data/. Download CIC-IDS2017 CSV flow files and place them in data/.")
}

message("Reading ", length(csv_files), " CSV file(s)...")
read_one <- function(f) {
  tryCatch(
    read.csv(f, stringsAsFactors = FALSE, check.names = FALSE,
             na.strings = c("", "NA", "NaN", "nan"), strip.white = TRUE),
    error = function(e) {
      warning("Could not read ", basename(f), ": ", conditionMessage(e))
      NULL
    }
  )
}
data_list <- lapply(csv_files, read_one)
data_list <- Filter(Negate(is.null), data_list)
if (length(data_list) == 0) stop("No CSV files could be read.")

# Keep only columns shared by all input files, to combine multiple daily CSVs safely.
common_cols <- Reduce(intersect, lapply(data_list, names))
if (length(common_cols) < 2) {
  stop("Input CSV files do not have enough common columns. Analyze one file at a time or use matching CIC-IDS2017 CSV formats.")
}
data_list <- lapply(data_list, function(x) x[, common_cols, drop = FALSE])
dat <- do.call(rbind, data_list)
rm(data_list)

# Remove leading/trailing whitespace from column names and labels.
names(dat) <- trimws(names(dat))
normalized_names <- tolower(gsub("[^A-Za-z0-9]", "", names(dat)))
print(names(dat))
print(normalized_names)
label_candidates <- c("label", "class", "attack", "target", "trafficlabel")
label_idx <- match(label_candidates, normalized_names)
label_idx <- label_idx[!is.na(label_idx)]
if (length(label_idx) == 0) {
  stop("Could not identify a label column. Expected a column such as Label or Class.")
}
label_col <- names(dat)[label_idx[1]]
raw_label <- trimws(as.character(dat[[label_col]]))
valid_label <- !is.na(raw_label) & nzchar(raw_label)
dat <- dat[valid_label, , drop = FALSE]
raw_label <- raw_label[valid_label]
dat$TargetAttack <- ifelse(grepl("BENIGN|NORMAL", raw_label, ignore.case = TRUE), 0, 1)
dat$TargetAttack <- as.integer(dat$TargetAttack)

# Convert non-target fields to numeric where possible.
feature_names <- setdiff(names(dat), c(label_col, "TargetAttack"))
for (nm in feature_names) {
  if (!is.numeric(dat[[nm]])) {
    old <- dat[[nm]]
    converted <- suppressWarnings(as.numeric(gsub(",", "", trimws(as.character(old)))))
    # Only accept conversion if at least half of non-empty values convert.
    nonempty <- !is.na(old) & nzchar(trimws(as.character(old)))
    if (sum(nonempty) > 0 && sum(!is.na(converted[nonempty])) / sum(nonempty) >= 0.5) {
      dat[[nm]] <- converted
    }
  }
}
numeric_features <- feature_names[vapply(dat[feature_names], is.numeric, logical(1))]
if (length(numeric_features) == 0) stop("No numeric feature columns were detected.")

# Replace infinite values and discard all-NA/constant features.
for (nm in numeric_features) {
  dat[[nm]][!is.finite(dat[[nm]])] <- NA_real_
}
usable <- numeric_features[vapply(dat[numeric_features], function(x) {
  x <- x[is.finite(x)]
  length(x) >= 10 && length(unique(x)) > 1
}, logical(1))]
if (length(usable) == 0) stop("No usable numeric predictors after cleaning.")

# Use at most 50,000 rows to keep base-R analysis manageable.
max_rows <- 50000
if (nrow(dat) > max_rows) {
  # Stratified sampling preserves the benign/attack mix.
  i0 <- which(dat$TargetAttack == 0)
  i1 <- which(dat$TargetAttack == 1)
  n0 <- min(length(i0), floor(max_rows * length(i0) / nrow(dat)))
  n1 <- min(length(i1), max_rows - n0)
  chosen <- c(if (n0 > 0) sample(i0, n0),
              if (n1 > 0) sample(i1, n1))
  if (length(chosen) < max_rows) {
    remaining <- setdiff(seq_len(nrow(dat)), chosen)
    chosen <- c(chosen, sample(remaining, min(max_rows - length(chosen), length(remaining))))
  }
  dat <- dat[chosen, , drop = FALSE]
}
dat <- dat[!is.na(dat$TargetAttack), , drop = FALSE]
dat$TargetAttack <- as.integer(dat$TargetAttack)

# Write summary.
summary_path <- file.path(results_dir, "dataset_summary.txt")
sink(summary_path)
cat("PROJECT: Statistical Detection of Cyberattacks Using Network Traffic Data\n")
cat("Student: Sakthi Shivram M | RegNo: 24BYB1168\n\n")
cat("Input files:\n"); print(basename(csv_files))
cat("\nLabel column:", label_col, "\n")
cat("Rows analyzed:", nrow(dat), "\n")
cat("Numeric candidate features:", length(numeric_features), "\n")
cat("Usable features:", length(usable), "\n")
cat("Class counts (0=benign, 1=attack):\n"); print(table(dat$TargetAttack))
cat("\nLabel values observed:\n"); print(sort(unique(raw_label)))
sink()

# Descriptive statistics for all usable numeric features by class.
desc_rows <- list()
for (nm in usable) {
  for (cl in c(0, 1)) {
    x <- dat[[nm]][dat$TargetAttack == cl]
    x <- x[is.finite(x)]
    if (length(x) == 0) next
    desc_rows[[length(desc_rows) + 1]] <- data.frame(
      feature = nm, class = ifelse(cl == 0, "Benign", "Attack"),
      n = length(x), mean = mean(x), sd = sd(x),
      median = median(x), q1 = unname(quantile(x, 0.25)),
      q3 = unname(quantile(x, 0.75)), min = min(x), max = max(x)
    )
  }
}
desc <- do.call(rbind, desc_rows)
write.csv(desc, file.path(results_dir, "descriptive_statistics.csv"), row.names = FALSE)

# Select features with the most complete observations and manageable scales.
missing_rate <- vapply(dat[usable], function(x) mean(!is.finite(x)), numeric(1))
candidate <- names(sort(missing_rate))[seq_len(min(length(usable), 12))]
# Remove highly incomplete features and re-check variability.
candidate <- candidate[missing_rate[candidate] < 0.40]
candidate <- candidate[vapply(dat[candidate], function(x) {
  z <- x[is.finite(x)]
  length(unique(z)) > 1 && length(z) > 20
}, logical(1))]
if (length(candidate) == 0) stop("No predictors with sufficient non-missing data were found.")

# Plot the class balance.
png(file.path(plots_dir, "class_balance.png"), width = 1000, height = 700, res = 120)
barplot(table(factor(dat$TargetAttack, levels = c(0, 1),
                     labels = c("Benign", "Attack"))),
        main = "Network Flow Class Counts", ylab = "Number of flows",
        xlab = "Traffic class")
dev.off()

# Plot histograms and boxplots for up to six features.
plot_features <- head(candidate, 6)
for (nm in plot_features) {
  safe_nm <- gsub("[^A-Za-z0-9_-]", "_", nm)
  x0 <- dat[[nm]][dat$TargetAttack == 0]
  x1 <- dat[[nm]][dat$TargetAttack == 1]
  x0 <- x0[is.finite(x0)]; x1 <- x1[is.finite(x1)]
  png(file.path(plots_dir, paste0("hist_", safe_nm, ".png")),
      width = 1000, height = 700, res = 120)
  allx <- c(x0, x1)
  if (length(allx) > 1) {
    hist(allx, breaks = "FD", main = paste("Distribution:", nm),
         xlab = nm, col = "grey85", border = "white")
  }
  dev.off()
  png(file.path(plots_dir, paste0("boxplot_", safe_nm, ".png")),
      width = 1000, height = 700, res = 120)
  boxplot(x0, x1, names = c("Benign", "Attack"), main = paste(nm, "by traffic class"),
          ylab = nm, outline = FALSE)
  dev.off()
}

# Hypothesis tests: Welch t-test and Wilcoxon rank-sum test.
test_rows <- list()
for (nm in candidate) {
  x0 <- dat[[nm]][dat$TargetAttack == 0]
  x1 <- dat[[nm]][dat$TargetAttack == 1]
  x0 <- x0[is.finite(x0)]; x1 <- x1[is.finite(x1)]
  if (length(x0) < 2 || length(x1) < 2) next
  t_res <- tryCatch(t.test(x0, x1), error = function(e) NULL)
  w_res <- tryCatch(wilcox.test(x0, x1, exact = FALSE), error = function(e) NULL)
  test_rows[[length(test_rows) + 1]] <- data.frame(
    feature = nm,
    benign_n = length(x0), attack_n = length(x1),
    benign_mean = mean(x0), attack_mean = mean(x1),
    mean_difference_attack_minus_benign = mean(x1) - mean(x0),
    welch_t = if (!is.null(t_res)) unname(t_res$statistic) else NA_real_,
    welch_p = if (!is.null(t_res)) t_res$p.value else NA_real_,
    wilcoxon_statistic = if (!is.null(w_res)) unname(w_res$statistic) else NA_real_,
    wilcoxon_p = if (!is.null(w_res)) w_res$p.value else NA_real_
  )
}
tests <- if (length(test_rows)) do.call(rbind, test_rows) else data.frame()
if (nrow(tests) > 0) {
  tests$welch_p_adjusted_BH <- p.adjust(tests$welch_p, method = "BH")
  tests$wilcoxon_p_adjusted_BH <- p.adjust(tests$wilcoxon_p, method = "BH")
  tests <- tests[order(tests$welch_p_adjusted_BH), ]
}
write.csv(tests, file.path(results_dir, "hypothesis_tests.csv"), row.names = FALSE)

# Build a balanced, finite complete-case model dataset using candidate features.
model_features <- head(candidate, 8)
model_dat <- dat[, c("TargetAttack", model_features), drop = FALSE]
for (nm in model_features) {
  med <- median(model_dat[[nm]][is.finite(model_dat[[nm]])], na.rm = TRUE)
  if (!is.finite(med)) med <- 0
  model_dat[[nm]][!is.finite(model_dat[[nm]])] <- med
}
# Winsorize extreme values for numerical stability; thresholds are learned on this dataset.
for (nm in model_features) {
  q <- quantile(model_dat[[nm]], c(0.01, 0.99), na.rm = TRUE)
  if (all(is.finite(q)) && q[1] < q[2]) {
    model_dat[[nm]] <- pmin(pmax(model_dat[[nm]], q[1]), q[2])
  }
}
# Remove near-constant predictors and scale numeric columns.
model_features <- model_features[vapply(model_dat[model_features], function(x) {
  sd(x, na.rm = TRUE) > 0
}, logical(1))]
if (length(model_features) == 0) stop("All model predictors were constant.")
for (nm in model_features) {
  m <- mean(model_dat[[nm]])
  s <- sd(model_dat[[nm]])
  if (!is.finite(s) || s == 0) s <- 1
  model_dat[[nm]] <- (model_dat[[nm]] - m) / s
}

# Stratified 75/25 split.
idx0 <- which(model_dat$TargetAttack == 0)
idx1 <- which(model_dat$TargetAttack == 1)
if (length(idx0) < 4 || length(idx1) < 4) {
  stop("Need at least four benign and four attack rows for a train/test split.")
}
train_idx <- c(sample(idx0, max(2, floor(0.75 * length(idx0)))),
               sample(idx1, max(2, floor(0.75 * length(idx1)))))
test_idx <- setdiff(seq_len(nrow(model_dat)), train_idx)
train <- model_dat[train_idx, , drop = FALSE]
test <- model_dat[test_idx, , drop = FALSE]

# Fit logistic regression, dropping predictors if singular or convergence fails.
form <- as.formula(paste("TargetAttack ~", paste(sprintf("`%s`", model_features), collapse = " + ")))
fit <- tryCatch(glm(form, data = train, family = binomial()), error = function(e) NULL)
if (is.null(fit) || !isTRUE(fit$converged)) {
  # A smaller model is often more stable with correlated traffic features.
  model_features <- head(model_features, min(4, length(model_features)))
  form <- as.formula(paste("TargetAttack ~", paste(sprintf("`%s`", model_features), collapse = " + ")))
  fit <- glm(form, data = train, family = binomial())
}
prob <- as.numeric(predict(fit, newdata = test, type = "response"))
pred <- ifelse(prob >= 0.5, 1L, 0L)
actual <- test$TargetAttack
cm <- table(factor(actual, levels = c(0, 1), labels = c("Actual_Benign", "Actual_Attack")),
            factor(pred, levels = c(0, 1), labels = c("Pred_Benign", "Pred_Attack")))
tn <- as.numeric(cm["Actual_Benign", "Pred_Benign"])
fp <- as.numeric(cm["Actual_Benign", "Pred_Attack"])
fn <- as.numeric(cm["Actual_Attack", "Pred_Benign"])
tp <- as.numeric(cm["Actual_Attack", "Pred_Attack"])
safe_div <- function(a, b) if (b == 0) NA_real_ else a / b
wilson <- function(k, n, z = 1.96) {
  if (n <= 0) return(c(NA_real_, NA_real_))
  p <- k / n
  den <- 1 + z^2 / n
  center <- (p + z^2 / (2*n)) / den
  half <- z * sqrt((p*(1-p)/n) + z^2/(4*n^2)) / den
  c(max(0, center-half), min(1, center+half))
}
accuracy <- safe_div(tp + tn, sum(cm))
sensitivity <- safe_div(tp, tp + fn)
specificity <- safe_div(tn, tn + fp)
precision <- safe_div(tp, tp + fp)
f1 <- if (is.finite(precision) && is.finite(sensitivity) && precision + sensitivity > 0) {
  2 * precision * sensitivity / (precision + sensitivity)
} else NA_real_

# Base-R AUC using rank statistic, if both classes are represented.
auc_rank <- function(y, scores) {
  n1 <- sum(y == 1); n0 <- sum(y == 0)
  if (n1 == 0 || n0 == 0) return(NA_real_)
  r <- rank(scores, ties.method = "average")
  (sum(r[y == 1]) - n1*(n1+1)/2) / (n1*n0)
}
auc <- auc_rank(actual, prob)
acc_ci <- wilson(tp + tn, length(actual))
sens_ci <- wilson(tp, tp + fn)
spec_ci <- wilson(tn, tn + fp)

sink(file.path(results_dir, "model_metrics.txt"))
cat("LOGISTIC REGRESSION MODEL EVALUATION\n")
cat("Student: Sakthi Shivram M | RegNo: 24BYB1168\n\n")
cat("Training rows:", nrow(train), "\nTest rows:", nrow(test), "\n")
cat("Features used:", paste(model_features, collapse = ", "), "\n\n")
cat("Confusion matrix (rows=actual, columns=predicted):\n"); print(cm)
cat("\nMetrics (test set):\n")
cat(sprintf("Accuracy: %.4f\n", accuracy))
cat(sprintf("Accuracy approximate 95%% Wilson CI: [%.4f, %.4f]\n", acc_ci[1], acc_ci[2]))
cat(sprintf("Sensitivity/Recall: %.4f\n", sensitivity))
cat(sprintf("Sensitivity approximate 95%% Wilson CI: [%.4f, %.4f]\n", sens_ci[1], sens_ci[2]))
cat(sprintf("Specificity: %.4f\n", specificity))
cat(sprintf("Specificity approximate 95%% Wilson CI: [%.4f, %.4f]\n", spec_ci[1], spec_ci[2]))
cat(sprintf("Precision: %.4f\n", precision))
cat(sprintf("F1 score: %.4f\n", f1))
cat(sprintf("ROC-AUC (rank-based): %.4f\n", auc))
cat("\nInterpretation: these metrics describe this held-out random split only.\n")
cat("They do not guarantee performance on a different network or future traffic.\n")
sink()

coef_summary <- summary(fit)$coefficients
coef_df <- data.frame(term = rownames(coef_summary), estimate = coef_summary[,1],
                      std_error = coef_summary[,2], z_value = coef_summary[,3],
                      p_value = coef_summary[,4], row.names = NULL)
write.csv(coef_df, file.path(results_dir, "model_coefficients.csv"), row.names = FALSE)

# Plot ROC curve from ranked scores using a simple threshold sweep.
thresholds <- sort(unique(c(0, prob, 1)))
roc_points <- lapply(thresholds, function(th) {
  pp <- ifelse(prob >= th, 1L, 0L)
  c(fpr = safe_div(sum(pp == 1 & actual == 0), sum(actual == 0)),
    tpr = safe_div(sum(pp == 1 & actual == 1), sum(actual == 1)))
})
roc_mat <- do.call(rbind, roc_points)
roc_mat <- roc_mat[complete.cases(roc_mat), , drop = FALSE]
png(file.path(plots_dir, "roc_curve.png"), width = 900, height = 700, res = 120)
plot(roc_mat[, "fpr"], roc_mat[, "tpr"], type = "l", lwd = 2,
     xlim = c(0, 1), ylim = c(0, 1), xlab = "False Positive Rate",
     ylab = "True Positive Rate", main = paste("ROC Curve (AUC =", round(auc, 3), ")"))
abline(0, 1, lty = 2)
dev.off()

# Export predictions for transparent checking.
predictions <- data.frame(actual = actual, predicted = pred, attack_probability = prob)
write.csv(predictions, file.path(results_dir, "test_predictions.csv"), row.names = FALSE)

cat("\nAnalysis complete.\n")
cat("Read results/dataset_summary.txt, results/hypothesis_tests.csv, and results/model_metrics.txt.\n")
cat("Plots saved in plots/.\n")
