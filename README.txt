PROJECT: Statistical Detection of Cyberattacks Using Network Traffic Data
Student: Sakthi Shivram M
Register Number: 24BYB1168

OVERVIEW
This is a reproducible Probability and Statistics project in R. It analyzes network-traffic features and compares benign traffic with malicious traffic using descriptive statistics, visualizations, hypothesis testing, logistic regression, confidence intervals, and classification metrics.

IMPORTANT DATASET NOTE
The CIC-IDS2017 dataset is not bundled because it is large and has its own distribution terms. Download it from the official Canadian Institute for Cybersecurity page:
https://www.unb.ca/cic/datasets/ids-2017.html

Download one or more CIC-IDS2017 CSV flow files and place them in the data/ folder. The script accepts one or more CSV files. Keep the original class/Label column. The script searches for common label names and common numeric flow features.

QUICK START
1. Install R (https://cran.r-project.org/) and optionally RStudio.
2. Download CIC-IDS2017 CSV file(s) and place them in data/.
3. Open R/RStudio in this project folder.
4. Run: source("R/analysis.R")
5. Results and plots are written to results/ and plots/.

R PACKAGES
The script uses base R functions only. No extra packages are required.

STATISTICAL METHODS
- Descriptive statistics (mean, median, standard deviation, quartiles)
- Histograms and boxplots
- Welch two-sample t-test and Wilcoxon rank-sum test
- Pearson/Spearman correlation where applicable
- Logistic regression
- Train/test split and confusion-matrix metrics
- Approximate confidence intervals for sensitivity, specificity, and accuracy

DATA HANDLING
The script samples rows for practical runtime, cleans infinite/missing values, and removes constant or unusable predictors. Results depend on the chosen files and random seed. The script does not fabricate or pre-fill findings: all numerical results are computed from the downloaded dataset.

INTERPRETATION CAUTION
Network flow records from the same capture period can be correlated. A random row split can overestimate generalization to genuinely new environments. This project is an educational statistical analysis, not a production intrusion-detection system.
