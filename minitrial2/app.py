import pandas as pd
from flask import Flask, render_template, request
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from features import abc

app = Flask(__name__)

# Load your dataset into a pandas DataFrame
# Assuming your dataset is named 'df' with columns 'https', 'url_length', and 'class'
# Replace this with your actual dataset loading code
df = pd.read_csv('data1.csv')

# Split the dataset into features (X) and target variable (y)
X = df[['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                      'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                      'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards']]  # Features: HTTPS status and URL length in binary format
y = df['class']  # Target variable: Legitimate (1) or Phishing (0)

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train a Random Forest classifier
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
rf_classifier.fit(X_train, y_train)

def extract_features(url):
    # Logic for extracting features (URL length and HTTPS status) from the URL
    # Replace this with your actual feature extraction logic
    
   
  features = []
  #Address bar based features (10)
  #features.append(getDomain(url))
  features.append(havingIP(url))
  features.append(haveAtSign(url))
  features.append(getLength(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomain(url))
  features.append(tinyURL(url))
  features.append(prefixSuffix(url))
  
  #Domain based features (4)
  

  
  features.append(web_traffic(url))
  features.append(1 if dns == 1 else domainAge(domain_name))
  features.append(1 if dns == 1 else domainEnd(domain_name))
  
  # HTML & Javascript based features
  try:
    response = requests.get(url)
  except:
    response = ""

  features.append(iframe(response))
  features.append(mouseOver(response))
  features.append(rightClick(response))
  features.append(forwarding(response))
  
  return features

#converting the list to dataframe
feature_names = [ 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                      'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                      'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards', 'class']
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process_url', methods=['POST'])
def process_url():
    url = request.form['urlInput'].strip()
    
    # Extract features from the submitted URL
    url_features = extract_features(url)
    
    # Predict using the trained classifier
    prediction = rf_classifier.predict(url_features)
    result = "Legitimate" if prediction[0] == '0' else "Phishing"
    
    return render_template('result.html', url=url, result=result)
if __name__ == '__main__':
    app.run(debug=True)
