from flask import Flask, request, jsonify
from ultralytics import YOLO
import time
import os

app = Flask(__name__)
model = YOLO("AI_Models/best.pt")

@app.route("/analyze", methods=["POST"])
def analyze():
    if 'image' not in request.files:
        return jsonify({"error": "No image provided"}), 400

    image_file = request.files['image']
    image_path = os.path.join("temp_images", image_file.filename)
    os.makedirs("temp_images", exist_ok=True)
    image_file.save(image_path)

    start_time = time.time()
    results = model.predict(source=image_path, save=True)
    end_time = time.time()

    endResult = {}

    for r in results:
        sandStoneCount = 0
        siltStoneCount = 0
        class_pixel_counts = {"class_0": 0, "class_1": 0}
        total_pixels = r.orig_img.shape[0] * r.orig_img.shape[1]

        for box in r.boxes:
            cls_id = int(box.cls[0])
            if cls_id == 0:
                sandStoneCount += 1
            elif cls_id == 1:
                siltStoneCount += 1

        if r.masks is not None:
            masks = r.masks.data
            classes = r.boxes.cls
            for i, mask in enumerate(masks):
                cls_id = int(classes[i])
                label = model.names[cls_id]
                pixel_count = mask.sum().item()
                if label in class_pixel_counts:
                    class_pixel_counts[label] += pixel_count

        endResult.update({
            "sandStoneCount": sandStoneCount,
            "sandStoneCoverage": (class_pixel_counts["class_0"] / total_pixels) * 100,
            "siltStoneCount": siltStoneCount,
            "siltStoneCoverage": (class_pixel_counts["class_1"] / total_pixels) * 100,
            "inferenceTime": end_time - start_time
        })

    return jsonify(endResult)

if __name__ == "__main__":
    app.run(debug=True)