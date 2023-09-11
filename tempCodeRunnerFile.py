# Load the trained model
knn_model = joblib.load('model.pkl')

# Load the dataset
df = pd.read_csv('/content/drive/MyDrive/heart_disease_dataset.csv')

# Preprocess the dataset
X = df.drop('target', axis=1)
y = df['target']
scaler = StandardScaler()
X = scaler.fit_transform(X)

# Train the KNN model
knn_model = KNeighborsClassifier(n_neighbors=5)
knn_model.fit(X, y)
