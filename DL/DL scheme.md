
- **Feedforward NN**
	- **Issues with images**: 
		- *Spatial patterns and hierarchies*: if we have a face on the top left of an image and the same face on the bottom right of another image, they could be recognized as two different faces (or even two different objects), since the images are represented as arrays

- **Convolutional NN**: solves the issues with images of the simple feedforward NN.
	- **Applications**: mainly **images** (object recognition, face detection, image segmentation)
	- **Pre-trained ConvNets**

-  **Autoencoder**: NN that is trained to produce as output a duplicate of its input.
	- **Applications**: 
		- **Data generation**
		- **Data compression** (reducing dimensionality)
		- **Anomaly detection**
		- **Denoising** (removing noise from signals or images)
		- **Pre-training** (initializing weights for more complex models)
	- **Issues with overfitting**

- **VAE (Variational Autoencoder)**: solves the autoencoder overfitting problem.
	- **Applications**:
		- **Data Generation**: Creating synthetic images or signals.
		- **Interpolation**: Generating intermediate representations between two samples.
		- **Unsupervised Learning**: Exploring latent structures in datasets

- **GAN (Generative Adversarial Network)**: formed by two modules, a **generator** (used to generate some data) and a **discriminator** (used to understand if the input data is real or fake, that is it has been created by the generator or not)
	- **Applications**:
		- **Image Generation**: Creating realistic photos, digital art, synthetic faces
		- **Data Augmentation**: Generating new data to improve classifiers
		- **Super-Resolution**: Enhancing image resolution
		- **Anomaly Detection**: Used in quality control
		- **Style Transfer**: Applying artistic styles to images

	- **CycleGAN**
		- **Applications**:
			- **Style Transfer**: Converting images between styles (e.g., photo ↔ painting).
			- **Domain Translation**: Transforming images between conditions (e.g., day ↔ night, summer ↔ winter).
			- **Medicine**: Converting medical scans (e.g., CT ↔ MRI).
			- **Restoration**: Colorizing black-and-white photos.

	- **Conditional GAN**: a GAN which controls the nature of the output by conditioning on a label.
		- **Example**: **pix2pix**
		- **Applications**:
			- **Controlled Data Generation**: Creating images based on specific input criteria (e.g., categories).
			- **Text-to-Image Generation**: Drawing images from textual descriptions.
			- **Data Imputation**: Filling in missing data in structured datasets.


- **U-Net**: *U-shape* autoencoder
	- **Applications**:
		- **Medicine**: Segmenting organs, tumors, or other regions in diagnostic images.
		- **Computer Vision**: Delimiting objects in images (e.g., road segmentation for autonomous vehicles).

- **RNN (Recurrent NN)**: solves the following problem: feedforward networks don’t consider temporal states (that is, the input data size must be fixed and NN can't remember of data processed in the past)
	- **Vanishing gradient problem**: the derivative of the sigmoid is too small, meaning that the gradient is very close to 0, so the NN has found a plateau, hence the NN cannot learn anymore. The derivative of tanh is better, but it doesn’t solve the problem at all. Thus, the RNN cannot be used for large input data
	- **Short-term memory problem**: RNN can remember only what it has done in the very previous step, but not in the very past

	- **Applications**:
		- **Time Series Analysis**: Forecasting stock prices, analyzing signals.
		- **Natural Language Processing (NLP)**:
		    - Machine translation.
		    - Sentiment analysis.
		    - Text generation.
		- **Speech Recognition**: Converting audio to text.
		- **Video Analysis**: Temporal analysis of video sequences.

- **LSTM (Long Short Term Memory Network)**: solves the RNN's short-term memory problem and it can control the vanishing gradient
	- **Applications**:
		- **Advanced NLP**: Machine translation, chatbots, language modeling.
		- **Long-term Forecasting**: Predicting weather or financial signals.
		- **Activity Recognition**: Analyzing sequences in video or sensor data.
		- **Robotic Control**: Sequence-based planning.