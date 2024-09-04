import pandas as pd

# ------------------ Declarative Variables ------------------
# Default recommendation for missing CVEs
default_recommendation = "Segment or Microsegment the device (Default Recommendation)"

# Filenames for input and output
recommendations_filename = "Vulnerability_Recommendations.xlsx"
vulnerability_filename = "Vulnerability_List.xlsx"
output_filename = "Devices_and_Vulnerabilities_with_Recommendations.xlsx"
# -----------------------------------------------------------

# Step 1: Load all worksheets from the recommendations file and extract CVEs with their recommendations
recommendations_data = pd.concat(pd.read_excel(recommendations_filename, sheet_name=None), ignore_index=True)

# Combine all CVEs into a single list per recommendation
recommendations_data['All CVEs'] = ''

# Define possible CVE columns in the recommendations file (static)
for col in ['Open High Risk CVEs', 'Open Medium Risk CVEs', 'Open Low Risk CVEs']:
    if col in recommendations_data.columns:
        recommendations_data['All CVEs'] += recommendations_data[col].fillna('') + ','

# Clean up 'All CVEs' by removing trailing commas
recommendations_data['All CVEs'] = recommendations_data['All CVEs'].str.rstrip(',')

# Step 2: Create a DataFrame mapping unique CVEs to recommendations
cve_recommendations = []

for _, row in recommendations_data.iterrows():
    cves = row['All CVEs'].split(',')
    recommendation = row['Recommendations']
    for cve in cves:
        cve = cve.strip()
        if cve:  # Ensure CVE is not empty
            cve_recommendations.append({'CVE ID': cve, 'Recommendation': recommendation})

# Convert to DataFrame and drop duplicates to ensure one recommendation per unique CVE ID
cve_recommendations_df = pd.DataFrame(cve_recommendations).drop_duplicates(subset=['CVE ID'])

# Step 3: Load all worksheets from the vulnerability file and match CVEs with their recommendations
vuln_data = pd.concat(pd.read_excel(vulnerability_filename, sheet_name=None), ignore_index=True)

# Merge the vulnerability data with the CVE recommendations
merged_data = pd.merge(vuln_data, cve_recommendations_df, on='CVE ID', how='left')

# Fill in missing recommendations with the default value
merged_data['Recommendation'] = merged_data['Recommendation'].fillna(default_recommendation)

# Step 4: Save the output to multiple Excel worksheets if the row count exceeds Excel's limits
with pd.ExcelWriter(output_filename, engine='xlsxwriter') as writer:
    for i in range(0, len(merged_data), 1048576):  # Maximum rows per Excel sheet (static)
        sheet_name = f'Sheet_{i // 1048576 + 1}'
        merged_data.iloc[i:i + 1048576].to_excel(writer, sheet_name=sheet_name, index=False)

print(f"Output saved to {output_filename}")
