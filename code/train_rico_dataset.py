import os
import torch
import torch.nn as nn
import torch.optim as optim
import torch.backends.cudnn as cudnn
from torch.utils.data import DataLoader
from torchvision import datasets, transforms, models
from tqdm.auto import tqdm

########################
# 1. Basic Config
########################

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("Using device:", device)

# Enable CUDNN benchmark for faster training (when input sizes are fixed).
cudnn.benchmark = True

# Define paths (adapt to your environment)
train_dir = "./prepare_dataset/train"
val_dir   = "./prepare_dataset/val"
test_dir  = "./prepare_dataset/test"

# Hyperparameters
batch_size = 32
lr = 1e-3
num_epochs = 10
save_dir = "./models_checkpoints"  # where to save intermediate models
os.makedirs(save_dir, exist_ok=True)

########################
# 2. Data & Transforms
########################

# Common image size for EfficientNet-B0 is 224x224
img_size = 224

# Data augmentation for training
train_transforms = transforms.Compose([
    transforms.Resize((img_size, img_size)),
    transforms.RandomHorizontalFlip(),
    transforms.RandomRotation(10),
    transforms.ToTensor(),
    transforms.Normalize([0.485, 0.456, 0.406],  # ImageNet mean
                         [0.229, 0.224, 0.225])  # ImageNet std
])

# For validation/testing, typically just resize & normalize
val_transforms = transforms.Compose([
    transforms.Resize((img_size, img_size)),
    transforms.ToTensor(),
    transforms.Normalize([0.485, 0.456, 0.406],
                         [0.229, 0.224, 0.225])
])

# Use ImageFolder to automatically gather classes from directory structure
train_dataset = datasets.ImageFolder(root=train_dir, transform=train_transforms)
val_dataset   = datasets.ImageFolder(root=val_dir,   transform=val_transforms)
test_dataset  = datasets.ImageFolder(root=test_dir,  transform=val_transforms)

train_loader = DataLoader(
    train_dataset, batch_size=batch_size, shuffle=True,
    num_workers=2, pin_memory=True
)
val_loader = DataLoader(
    val_dataset, batch_size=batch_size, shuffle=False,
    num_workers=2, pin_memory=True
)
test_loader = DataLoader(
    test_dataset, batch_size=batch_size, shuffle=False,
    num_workers=2, pin_memory=True
)

# The classes (labels) are automatically read from subfolders in alphabetical order
class_names = train_dataset.classes
num_classes = len(class_names)
print("Classes found:", class_names)

########################
# 3. Model Definition
########################

# Load pretrained EfficientNet-B0 from torchvision (requires PyTorch >= 1.12)
#model = models.efficientnet_b0(pretrained=True)
# In PyTorch 2+, you should use 'weights=' to specify the pretrained weights:
model = models.efficientnet_b0(weights=models.EfficientNet_B0_Weights.IMAGENET1K_V1)

# Replace the classifier head
# For EfficientNet-B0, the classifier is model.classifier[1] (in older PyTorch)
# For newer PyTorch, it's model.classifier.fc or something similar. Let's check:
in_features = model.classifier[1].in_features
model.classifier[1] = nn.Linear(in_features, num_classes)

# Move model to device (GPU or CPU)
model = model.to(device)

########################
# 4. Loss & Optimizer
########################
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=lr)

########################
# 5. Training Loop
########################

def train_one_epoch(epoch):
    model.train()
    running_loss = 0.0
    correct = 0
    total = 0
    
    # Use tqdm to visualize progress per batch
    loop = tqdm(train_loader, desc=f"Epoch [{epoch+1}/{num_epochs}] - Train")
    
    for images, labels in loop:
        images, labels = images.to(device), labels.to(device)
        
        optimizer.zero_grad()
        outputs = model(images)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()
        
        running_loss += loss.item() * images.size(0)
        _, predicted = torch.max(outputs, 1)
        correct += (predicted == labels).sum().item()
        total += labels.size(0)
        
        # Update tqdm description
        loop.set_postfix({
            "loss": f"{loss.item():.4f}",
            "acc": f"{(correct/total)*100:.2f}%"
        })
    
    epoch_loss = running_loss / total
    epoch_acc = correct / total
    return epoch_loss, epoch_acc


def validate_one_epoch(epoch):
    model.eval()
    running_loss = 0.0
    correct = 0
    total = 0
    
    # We don't need gradients for validation
    with torch.no_grad():
        loop = tqdm(val_loader, desc=f"Epoch [{epoch+1}/{num_epochs}] - Val")
        for images, labels in loop:
            images, labels = images.to(device), labels.to(device)
            outputs = model(images)
            loss = criterion(outputs, labels)
            
            running_loss += loss.item() * images.size(0)
            _, predicted = torch.max(outputs, 1)
            correct += (predicted == labels).sum().item()
            total += labels.size(0)
            
            loop.set_postfix({
                "loss": f"{loss.item():.4f}",
                "acc": f"{(correct/total)*100:.2f}%"
            })
    
    epoch_loss = running_loss / total
    epoch_acc = correct / total
    return epoch_loss, epoch_acc


best_val_acc = 0.0

for epoch in range(num_epochs):
    train_loss, train_acc = train_one_epoch(epoch)
    val_loss, val_acc = validate_one_epoch(epoch)
    
    print(f"Epoch [{epoch+1}/{num_epochs}] -> "
          f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f} | "
          f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}")
    
    # Save intermediate model for each epoch
    checkpoint_path = os.path.join(save_dir, f"model_epoch_{epoch+1}.pth")
    torch.save(model.state_dict(), checkpoint_path)
    print(f"Saved model checkpoint to: {checkpoint_path}")
    
    # Track best model
    if val_acc > best_val_acc:
        best_val_acc = val_acc
        best_model_path = os.path.join(save_dir, "best_model.pth")
        torch.save(model.state_dict(), best_model_path)
        print("New best model saved!")

########################
# 6. Evaluate on Test Set
########################

def evaluate(dataloader):
    model.eval()
    correct = 0
    total = 0
    with torch.no_grad():
        for images, labels in tqdm(dataloader, desc="Test"):
            images, labels = images.to(device), labels.to(device)
            outputs = model(images)
            _, predicted = torch.max(outputs, 1)
            correct += (predicted == labels).sum().item()
            total += labels.size(0)
    return correct / total

test_acc = evaluate(test_loader)
print(f"Test accuracy: {test_acc*100:.2f}%")

# Final save (if you want a final version beyond best model)
final_model_path = os.path.join(save_dir, "final_model.pth")
torch.save(model.state_dict(), final_model_path)
print("Training complete. Final model saved!")
