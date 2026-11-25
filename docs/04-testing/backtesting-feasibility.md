# Malawi Water-Point Dataset: Backtesting Feasibility

## Dataset
Source file: `malawi_waterpoint_source.csv`

## Verified observations
- Source records: 684
- Records with water-point name, GPS and submitted date: 684
- Repeated name-and-GPS groups: 234
- Repeated groups with differing recorded statuses: 94
- Consecutive dated observation intervals: 397
- Intervals of 28 days or less: 3
- Intervals longer than 28 days: 394
- Median interval: 79.0 days

## Assessment
The dataset contains repeated historical observations and recorded functionality
changes. However, only 3 consecutive intervals are
within the required four-week horizon.

The dataset alone is therefore insufficient for a reliable four-week
rolling-origin failure-prediction evaluation. Later observations must not be
incorrectly labelled as failures within four weeks when the observation gap
exceeds 28 days.

## Limitations and recommended action
- Treat water-point names and GPS as a matching key, not a guaranteed permanent ID.
- Retain unknown and partially functional states separately.
- Do not treat abandoned water points automatically as equipment failures.
- Record missing or ambiguous outcomes as unknown/censored, not as negative cases.
- Obtain additional dated follow-up observations before claiming that the
  four-week backtesting requirement has been met.

## Reproducibility
This report was generated from the downloaded CSV. The original CSV was not modified.
