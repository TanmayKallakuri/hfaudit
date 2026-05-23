from __future__ import annotations

# Known-safe TensorFlow ops. Ops not in this set are flagged as suspicious.
# Intentionally tight: unknown ops get medium-severity findings, not silence.
SAFE_TF_OPS: frozenset[str] = frozenset({
    # Math
    "Add", "AddN", "AddV2", "Sub", "Mul", "Div", "RealDiv", "FloorDiv", "TruncateDiv",
    "Mod", "FloorMod", "Pow", "Sqrt", "Rsqrt", "Exp", "Log", "Log1p", "Abs", "Neg",
    "Sign", "Ceil", "Floor", "Round", "Rint", "Maximum", "Minimum", "Square",
    "SquaredDifference", "Reciprocal", "Sin", "Cos", "Tan", "Asin", "Acos", "Atan",
    "Atan2", "Sinh", "Cosh", "Tanh", "Asinh", "Acosh", "Atanh", "Erf", "Erfc",
    "Lgamma", "Digamma", "BesselI0e", "BesselI1e", "Expm1",
    # Comparison / logical
    "Equal", "NotEqual", "Less", "LessEqual", "Greater", "GreaterEqual",
    "LogicalAnd", "LogicalOr", "LogicalNot", "Select", "SelectV2", "Where",
    # Reduction
    "Sum", "Mean", "Prod", "Max", "Min", "Any", "All",
    "ReduceSum", "ReduceMean", "ReduceProd", "ReduceMax", "ReduceMin",
    # Linear algebra
    "MatMul", "BatchMatMul", "BatchMatMulV2", "BatchMatMulV3",
    "Einsum", "Cross", "Qr", "Svd", "MatrixDeterminant", "MatrixInverse",
    "Cholesky", "SelfAdjointEigV2", "MatrixSolveLs",
    # NN layers
    "Conv2D", "Conv3D", "DepthwiseConv2dNative", "Conv2DBackpropInput",
    "Conv2DBackpropFilter", "Conv3DBackpropInputV2", "Conv3DBackpropFilterV2",
    "MaxPool", "MaxPoolV2", "MaxPool3D", "AvgPool", "AvgPool3D",
    "MaxPoolWithArgmax", "FractionalMaxPool", "FractionalAvgPool",
    # NN activations
    "Relu", "Relu6", "LeakyRelu", "Elu", "Selu", "Sigmoid", "Softmax", "LogSoftmax",
    "Softplus", "Softsign", "Swish",
    # NN normalization
    "FusedBatchNorm", "FusedBatchNormV2", "FusedBatchNormV3",
    "FusedBatchNormGrad", "FusedBatchNormGradV2", "FusedBatchNormGradV3",
    "L2Loss", "LRN",
    # NN misc
    "BiasAdd", "Dropout", "SparseSoftmaxCrossEntropyWithLogits",
    "SoftmaxCrossEntropyWithLogits", "TopKV2",
    # Data / tensor manipulation
    "Const", "Placeholder", "PlaceholderV2", "PlaceholderWithDefault",
    "Identity", "IdentityN", "StopGradient", "PreventGradient",
    "Reshape", "ExpandDims", "Squeeze", "Transpose",
    "Concat", "ConcatV2", "Pack", "Unpack", "Stack", "Unstack",
    "Slice", "StridedSlice", "Gather", "GatherV2", "GatherNd",
    "ScatterNd", "ScatterUpdate",
    "Tile", "Pad", "PadV2", "MirrorPad",
    "Split", "SplitV", "Reverse", "ReverseV2", "ReverseSequence",
    "SpaceToBatchND", "BatchToSpaceND", "DepthToSpace", "SpaceToDepth",
    "OneHot", "BroadcastTo", "BroadcastArgs", "BroadcastGradientArgs",
    "Fill", "ZerosLike", "OnesLike", "Range", "LinSpace",
    "Unique", "UniqueV2", "InvertPermutation",
    # Shape / size
    "Shape", "ShapeN", "Rank", "Size", "TensorShape",
    "DynamicStitch", "DynamicPartition",
    # Variable ops
    "VariableV2", "VarHandleOp", "ReadVariableOp", "AssignVariableOp",
    "AssignAddVariableOp", "AssignSubVariableOp",
    "ResourceGather", "ResourceScatterUpdate",
    "VarIsInitializedOp", "IsVariableInitialized",
    # Cast / type
    "Cast", "Bitcast", "CheckNumerics",
    # Random
    "RandomUniform", "RandomStandardNormal", "TruncatedNormal",
    "RandomShuffle", "Multinomial", "RandomUniformInt",
    "StatelessRandomUniformV2", "StatelessRandomNormalV2",
    "StatelessTruncatedNormalV2",
    # Control flow
    "NoOp", "Assert", "Merge", "Switch", "Enter", "Exit", "NextIteration",
    "LoopCond", "While", "If", "Case", "StatelessIf", "StatelessWhile",
    "PartitionedCall", "StatefulPartitionedCall",
    # Function / call
    "FunctionCall",
    # Dataset / iterator
    "IteratorV2", "MakeIterator", "IteratorGetNext", "IteratorGetNextSync",
    "IteratorToStringHandle", "IteratorFromStringHandle",
    "OptionalFromValue", "OptionalGetValue", "OptionalHasValue", "OptionalNone",
    "TensorSliceDataset", "BatchDatasetV2", "ShuffleDatasetV3",
    "MapDataset", "ParallelMapDatasetV2", "PrefetchDataset", "RepeatDataset",
    "ShardDataset", "CacheDatasetV2", "TakeDataset", "SkipDataset",
    "ZipDataset", "ConcatenateDataset", "RangeDataset",
    # Embedding
    "ResourceGatherNd",
    # String (benign standalone usage, but traced when feeding dangerous sinks)
    "StringJoin", "StringFormat", "ReduceJoin", "StringSplit", "StringSplitV2",
    "StringLength", "StringLower", "StringUpper", "StringStrip",
    "RegexReplace", "RegexFullMatch", "StaticRegexReplace", "StaticRegexFullMatch",
    "Substr", "UnicodeTranscode", "UnicodeScript", "UnicodeEncode", "UnicodeDecode",
    "DecodeBase64", "EncodeBase64",
    "AsString",
    # Sparse
    "SparseToDense", "SparseTensorDenseMatMul", "SparseReshape",
    "SparseReorder", "SparseFillEmptyRows",
    # Image (common in preprocessing)
    "DecodeJpeg", "DecodePng", "DecodeImage", "DecodeBmp", "DecodeGif",
    "EncodeJpeg", "EncodePng",
    "ResizeBilinear", "ResizeNearestNeighbor", "ResizeBicubic",
    "CropAndResize", "AdjustContrastv2", "AdjustHue", "AdjustSaturation",
    "RGBToHSV", "HSVToRGB",
    # Quantization
    "QuantizeV2", "Dequantize", "FakeQuantWithMinMaxVars",
    "FakeQuantWithMinMaxVarsPerChannel",
    # TPU / XLA markers (benign metadata ops)
    "XlaSharding", "XlaDynamicSlice", "Placeholder_XLA",
    "ConfigureDistributedTPU", "TPUReplicateMetadata",
    # SavedModel internal ops
    "SaveV2", "RestoreV2", "MergeV2Checkpoints", "ShardedFilename",
    # Misc safe
    "Snapshot", "Print", "Timestamp",
    "TensorListReserve", "TensorListSetItem", "TensorListGetItem",
    "TensorListStack", "TensorListFromTensor", "TensorListLength",
    "TensorListPushBack", "TensorListPopBack",
    "EmptyTensorList", "TensorListResize",
    "HashTableV2", "LookupTableFindV2", "LookupTableInsertV2",
    "LookupTableSizeV2", "InitializeTableFromTextFileV2",
    "MutableHashTableV2", "MutableHashTableOfTensorsV2",
    "MapPeek", "MapStage", "MapSize", "MapClear", "MapIncompleteSize",
    "OrderedMapPeek", "OrderedMapStage", "OrderedMapSize",
    "Barrier", "BarrierInsertMany", "BarrierTakeMany", "BarrierClose",
    "StackV2", "StackPushV2", "StackPopV2", "StackCloseV2",
    "QueueDequeueV2", "QueueEnqueueV2", "FIFOQueueV2", "PaddingFIFOQueueV2",
    "RandomShuffleQueueV2",
})
