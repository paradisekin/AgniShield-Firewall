import requests
from bs4 import BeautifulSoup
import os
import urllib
from PIL import Image
import pytesseract
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# Step 1: Extract images from the URL
def extract_images(url, max_images=10):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    img_tags = soup.find_all('img')
    os.makedirs('downloaded_images', exist_ok=True)

    images = []
    for img in img_tags:
        if len(images) >= max_images:
            break
        
        img_url = img.get('src')
        if not img_url:
            continue

        if not img_url.startswith(('http:', 'https:')):
            img_url = urllib.parse.urljoin(url, img_url)

        img_name = os.path.basename(img_url)

        # Check if the image has a valid extension (PNG, JPEG, JPG)
        if img_name.lower().endswith(('.png', '.jpg', '.jpeg')):
            img_path = os.path.join('downloaded_images', img_name)
            
            # Download and save the image
            img_data = requests.get(img_url).content
            with open(img_path, 'wb') as img_file:
                img_file.write(img_data)

            images.append(img_path)
            print(f"Downloaded {img_name}")
    
    return images

# Step 2: Convert images to text using OCR
def images_to_text(images):
    extracted_texts = []
    for image_path in images:
        image = Image.open(image_path)
        extracted_text = pytesseract.image_to_string(image)
        extracted_texts.append(extracted_text)
        print(f"Extracted text from {image_path}: {extracted_text}")
    
    return extracted_texts

# Step 3: Predict spam for extracted text
def predict_spam(extracted_texts, model, vectorizer, threshold=0.5):
    spam_count = 0
    ham_count = 0

    for text in extracted_texts:
        input_vectorized = vectorizer.transform([text])
        prediction = model.predict(input_vectorized)
        result = 'Spam' if prediction[0] == 'spam' else 'Ham'
        
        if result == 'Spam':
            spam_count += 1
        else:
            ham_count += 1
        
        print(f"The text is: {result}")
    
    # Determine whether to block or allow based on the threshold
    total_texts = len(extracted_texts)
    spam_proportion = spam_count / total_texts if total_texts > 0 else 0
    action = 'Block' if spam_proportion >= threshold else 'Allow'
    
    return spam_count, ham_count, action

# Step 4: Prepare the spam detection model
def prepare_spam_model():
    df = pd.read_csv('spam.csv', encoding='ISO-8859-1')
    X = df['v2']
    y = df['v1']
    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred)
    print(f"Model Accuracy: {accuracy}\n")
    print(report)
    
    return rf, vectorizer

# Step 5: Delete images after processing
def delete_images(images):
    for image_path in images:
        try:
            os.remove(image_path)
            print(f"Deleted {image_path}")
        except OSError as e:
            print(f"Error: {image_path} : {e.strerror}")

# Main function to combine everything
def main(url, threshold=0.5):
    # Step 1: Extract images
    images = extract_images(url, max_images=10)
    
    # Step 2: Convert images to text
    extracted_texts = images_to_text(images)
    
    # Step 3: Prepare the spam detection model
    rf, vectorizer = prepare_spam_model()
    
    # Step 4: Predict spam/ham for each extracted text
    spam_count, ham_count, action = predict_spam(extracted_texts, rf, vectorizer, threshold)
    
    # Step 5: Delete the images after processing
    delete_images(images)
    
    # Step 6: Print spam and ham counts and the final action
    print(f"Total Spam messages: {spam_count}")
    print(f"Total Ham messages: {ham_count}")
    print(f"Action: {action} the address")
