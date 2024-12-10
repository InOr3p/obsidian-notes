
- **Feedforward NN**
	- **Issues with images**: 
		- *Spatial patterns and hierarchies*: if we have a face on the top left of an image and the same face on the bottom right of another image, they could be recognized as two different faces (or even two different objects), since the images are represented as arrays

- **Convolutional NN**: solves the issues with images of the simple feedforward NN.
	- **Applications**: mainly **images**
	- **Pre-trained ConvNets**

-  **Autoencoder**: NN that is trained to produce as output a duplicate of its input.
	- **Applications**: data **generation**
	- **Issues with overfitting**

- **VAE (Variational Autoencoder)**: solves the autoencoder overfitting problem

- **GAN (Generative Adversarial Network)**: formed by two modules, a **generator** (used to generate some data) and a **discriminator** (used to understand if the input data is real or fake, that is it has been created by the generator or not)
	- **CycleGAN**
	- **Conditional GAN**: a GAN which controls the nature of the output by conditioning on a label.
		- **Example**: **pix2pix**

- **U-Net**: *U-shape* autoencoder

- **RNN (Recurrent NN)**: solves the following problem: feedforward networks don’t consider temporal states (that is, the input data size must be fixed and NN can't remember of data processed in the past)
	- **Vanishing gradient problem**: the derivative of the sigmoid is too small, meaning that the gradient is very close to 0, so the NN has found a plateau, hence the NN cannot learn anymore. The derivative of tanh is better, but it doesn’t solve the problem at all. Thus, the RNN cannot be used for large input data
	- **Short-term memory problem**: RNN can remember only what it has done in the very previous step, but not in the very past

- **LSTM (Long Short Term Memory Network)**: solves the RNN's short-term memory problem and it can control the vanishing gradient