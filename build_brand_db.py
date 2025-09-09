# build_brand_db.py
import os, pickle
from PIL import Image
import imagehash
import numpy as np
from tensorflow.keras.applications import MobileNetV2
from tensorflow.keras.preprocessing import image as keras_image
from tensorflow.keras.applications.mobilenet_v2 import preprocess_input

BRAND_DIR = "brands"    # folder with images named brand.png
OUTFILE = "brand_db.pkl"

# compute perceptual hash and optionally embedding
brand_db = {}

# optional cnn model for embeddings
try:
    cnn = MobileNetV2(weights="imagenet", include_top=False, pooling="avg")
    use_cnn = True
except Exception:
    cnn = None
    use_cnn = False

for fname in os.listdir(BRAND_DIR):
    if not fname.lower().endswith((".png", ".jpg", ".jpeg")):
        continue
    brand_name = os.path.splitext(fname)[0]
    img_path = os.path.join(BRAND_DIR, fname)
    img = Image.open(img_path).convert("RGB").resize((380,380))
    phash = str(imagehash.phash(img))   # string hex
    data = {"phash": phash}
    if use_cnn:
        x = keras_image.img_to_array(img.resize((224,224)))
        x = np.expand_dims(x, axis=0)
        x = preprocess_input(x)
        emb = cnn.predict(x)[0]  # 1D vector
        data["embedding"] = emb
    brand_db[brand_name] = data

with open(OUTFILE, "wb") as f:
    pickle.dump(brand_db, f)

print("Brand DB saved:", OUTFILE)
