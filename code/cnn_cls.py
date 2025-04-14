import io
import torch
import torch.nn as nn
from torchvision import models, transforms, datasets
from PIL import Image

from utils import time_consumed

# 1. Classes in alphabetical order, same as your training set
class_names = ['ICON_ARROW_BACKWARD', 'ICON_ARROW_DOWNWARD', 'ICON_ARROW_FORWARD', 'ICON_ARROW_UPWARD', 'ICON_ASSISTANT', 'ICON_CALENDAR', 'ICON_CALL', 'ICON_CAST', 'ICON_CHAT', 'ICON_CHECK', 'ICON_CLOUD', 'ICON_COMPASS', 'ICON_CONTRACT', 'ICON_DELETE', 'ICON_DOWNLOAD', 'ICON_EDIT', 'ICON_END_CALL', 'ICON_ENVELOPE', 'ICON_EXPAND', 'ICON_FACEBOOK', 'ICON_GALLERY', 'ICON_GOOGLE', 'ICON_HAPPY_FACE', 'ICON_HEADSET', 'ICON_HEART', 'ICON_HISTORY', 'ICON_HOME', 'ICON_INFO', 'ICON_LAUNCH_APPS', 'ICON_LIST', 'ICON_LOCATION', 'ICON_MAGNIFYING_GLASS', 'ICON_MIC', 'ICON_MIC_MUTE', 'ICON_MOON', 'ICON_NAV_BAR_CIRCLE', 'ICON_NAV_BAR_RECT', 'ICON_NOTIFICATIONS', 'ICON_PAPERCLIP', 'ICON_PAUSE', 'ICON_PEOPLE', 'ICON_PERSON', 'ICON_PLAY', 'ICON_PLUS', 'ICON_QUESTION', 'ICON_REDO', 'ICON_REFRESH', 'ICON_SAD_FACE', 'ICON_SEND', 'ICON_SETTINGS', 'ICON_SHARE', 'ICON_SHOPPING_BAG', 'ICON_SHOPPING_CART', 'ICON_STAR', 'ICON_STOP', 'ICON_SUN', 'ICON_TAKE_PHOTO', 'ICON_THREE_BARS', 'ICON_THREE_DOTS', 'ICON_THUMBS_DOWN', 'ICON_THUMBS_UP', 'ICON_TIME', 'ICON_TWITTER', 'ICON_UNDO', 'ICON_UPLOAD', 'ICON_VIDEOCAM', 'ICON_VOLUME_DOWN', 'ICON_VOLUME_MUTE', 'ICON_VOLUME_STATE', 'ICON_VOLUME_UP', 'ICON_V_BACKWARD', 'ICON_V_DOWNWARD', 'ICON_V_FORWARD', 'ICON_V_UPWARD', 'ICON_X']
num_classes = len(class_names)

# 2. Create the same model architecture
#    Instead of pretrained=True, we should use weights='IMAGENET1K_V1' (PyTorch >= 2.0)
model = models.efficientnet_b0(weights=None)  # we will load our custom weights, so set weights=None
# If using PyTorch < 2.0, you might do: 
#   model = models.efficientnet_b0(weights=models.EfficientNet_B0_Weights.IMAGENET1K_V1)
# But in many cases, you just pass None if you're going to load your own .pth file.

# Update the classifier to match our number of classes
in_features = model.classifier[1].in_features
model.classifier[1] = nn.Linear(in_features, num_classes)

# 3. Load your saved weights
checkpoint_path = "best_model.pth"  # or "final_model.pth", or "model_epoch_N.pth"
# The future warning about torch.load: You can set weights_only=True in newer PyTorch versions if you want.
model.load_state_dict(torch.load(checkpoint_path, map_location="cpu", weights_only=True))

# Switch model to eval mode for inference
model.eval()

# 4. Define the same transforms used during training
img_size = 224
inference_transforms = transforms.Compose([
    transforms.Resize((img_size, img_size)),
    transforms.ToTensor(),
    transforms.Normalize([0.485, 0.456, 0.406],
                         [0.229, 0.224, 0.225])
])

class EfficientNetClient:
    @staticmethod
    @time_consumed
    def classify(image: io.BytesIO) -> str:
        img = Image.open(image).convert("RGB")  # ensure 3 channels
        img_t = inference_transforms(img).unsqueeze(0)  # shape (1, 3, 224, 224)

        with torch.no_grad():
            outputs = model(img_t)
            _, predicted = torch.max(outputs, 1)
            predicted_class = class_names[predicted.item()]
            confidence = torch.softmax(outputs, dim=1)[0, predicted.item()].item()

        return predicted_class, confidence
