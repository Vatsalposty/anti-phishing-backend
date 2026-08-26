import pandas as pd
import os

print("Loading original Kaggle dataset...")
df1 = pd.read_csv('malicious_phish.csv')
print(f"Original size: {len(df1)}")
# Kaggle format: url, type
# Map 'type' to 'label': benign -> 0, malicious/defacement/phishing -> 1
df1['label'] = df1['type'].apply(lambda x: 0 if x == 'benign' else 1)
df1 = df1[['url', 'label']]

print("Loading new GitHub dataset...")
df2 = pd.read_csv('new_dataset.csv')
print(f"New dataset size: {len(df2)}")
# GitHub format: URL, label
df2 = df2.rename(columns={'URL': 'url'})
df2 = df2[['url', 'label']]

print("Combining datasets...")
df_combined = pd.concat([df1, df2], ignore_index=True)
print(f"Combined size before dedup: {len(df_combined)}")

df_combined = df_combined[~df_combined.duplicated(subset=['url'])]  # type: ignore
print(f"Combined size after dedup: {len(df_combined)}")

print("Saving combined dataset...")
df_combined.to_csv('combined_massive_dataset.csv', index=False)  # type: ignore
print("Done! File saved as combined_massive_dataset.csv")
