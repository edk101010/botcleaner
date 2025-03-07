import streamlit as st
import pandas as pd
import unicodedata
import re

# Define extended list of suspicious domains
extended_disposable_domains = [
    'mailinator.com', 'yopmail.com', 'tempmail.com', 'trashmail.com', '10minutemail.com',
    'guerrillamail.com', 'sharklasers.com', 'dispostable.com', 'maildrop.cc',
    'sniffies.com', 'proton.me', 'gmail.con', 'uhxaqwvkcpqnbk.us', 'melw.kfyfhmeqybfky.us'
]

email_gibberish_pattern = re.compile(r"([a-zA-Z0-9])\1{5,}|^[a-zA-Z0-9]{30,}@|@([a-zA-Z0-9])\2{5,}\.")

def count_unicode_trickery(text):
    if not isinstance(text, str):
        return 0
    return sum(1 for char in text if ord(char) > 127)

# Streamlit interface
st.title("CSV Bot Detector")
st.write("Upload a CSV file to detect bots and suspicious submissions")

uploaded_file = st.file_uploader("Choose a CSV file", type="csv")

if uploaded_file is not None:
    # Read the CSV
    data = pd.read_csv(uploaded_file)
    
    # Process the data
    def detect_spam_status(row):
        normalized_address = unicodedata.normalize('NFKC', row['Mailing Address (Street Address)']).lower()
        # Bot detection first
        if re.search(r'(4016|4018)\s*n\s*lockwood\s*ave', normalized_address):
            return 'Bot'
        if count_unicode_trickery(row['Mailing Address (Street Address)']) > 3:
            return 'Bot'
        if re.search(r'^\d+$', normalized_address):
            return 'Bot'
        if row['Mailing Address (State / Province)'].strip().lower() != 'ohio':
            return 'Bot'
        if any(ua in row['User Agent'] for ua in ['MSIE 6.0', 'Windows NT 5.1']):
            return 'Bot'
        # Review detection
        email_domain = row['Email (Enter Email)'].split('@')[-1].lower()
        email_full = row['Email (Enter Email)'].lower()
        if email_domain in extended_disposable_domains:
            return 'Review - Suspicious Email Domain'
        if email_gibberish_pattern.search(email_full):
            return 'Review - Suspicious Email Pattern'
        ip_count = data['User IP'].value_counts().get(row['User IP'], 0)
        if ip_count > 2:
            return 'Review - Too Many from Same IP'
        if '?vnrosnrosee=yes' in row['Source Url']:
            return 'Review - Suspicious Query String'
        return 'Legit'
    
    data['Spam Status'] = data.apply(detect_spam_status, axis=1)
    
    # Summary counts
    bots = (data['Spam Status'] == 'Bot').sum()
    legit = (data['Spam Status'] == 'Legit').sum()
    review = data['Spam Status'].str.contains('Review').sum()
    
    # Display summary
    st.header("Results")
    st.write(f"Bots removed: {bots}")
    st.write(f"Review cases: {review}")
    st.write(f"Legit entries: {legit}")
    
    # Download buttons
    cleaned_data = data[data['Spam Status'] != 'Bot']
    st.download_button(
        label="Download Cleaned Data (bots removed)",
        data=cleaned_data.to_csv(index=False),
        file_name="cleaned_data.csv",
        mime="text/csv"
    )
    
    # Show data
    st.dataframe(data)